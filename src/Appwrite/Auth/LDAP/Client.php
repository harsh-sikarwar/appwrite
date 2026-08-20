<?php

namespace Appwrite\Auth\LDAP;

use Appwrite\Extend\Exception as AppwriteException;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Authenticates a user against one directory server.
 *
 * The flow is search-then-bind, which is what directories in the wild expect:
 * bind as a service account, search the subtree for the entry matching the
 * value the user signed in with, then attempt a second bind as that entry's DN
 * using the password they supplied. A successful second bind is the proof of
 * identity; the password is never compared by us and never stored.
 *
 * FreeDSx is used rather than ext-ldap deliberately. It is pure PHP over
 * stream_socket_client, which Swoole's SWOOLE_HOOK_TCP hooks, so binds are
 * non-blocking inside a coroutine. ext-ldap has no Swoole hook and would stall
 * the worker's event loop on every sign-in.
 */
class Client
{
    /**
     * Long enough for a directory across a VPN, short enough that a dead server
     * fails the request rather than holding it open.
     */
    private const int TIMEOUT_CONNECT = 5;
    private const int TIMEOUT_OPERATION = 10;

    public function __construct(private readonly Settings $settings)
    {
    }

    /**
     * Verify a user's credentials and return their directory entry.
     *
     * Returns null when the user does not exist, the password is wrong, or the
     * user does not satisfy the provisioning filter. These are deliberately
     * indistinguishable to the caller: telling them apart would let anyone probe
     * the directory for valid usernames.
     *
     * @param string $username
     * @param string $password
     *
     * @return Identity|null
     *
     * @throws Exception when the directory cannot be reached or queried, which
     *                   is a server fault rather than a failed sign-in.
     */
    public function authenticate(string $username, string $password): ?Identity
    {
        // A directory will happily accept an empty password as an "unauthenticated
        // bind" and report success, which would authenticate anyone.
        if ($password === '') {
            return null;
        }

        $client = $this->connect();

        try {
            $this->bindService($client);

            $entry = $this->findEntry($client, $username);

            if ($entry === null) {
                return null;
            }

            if (!$this->bindUser($entry['dn'], $password)) {
                return null;
            }

            return new Identity($entry['dn'], $entry['email'], $entry['name']);
        } finally {
            $client->unbind();
        }
    }

    /**
     * Prove the configuration works, for the console's benefit.
     *
     * Only connects and binds the service account: it deliberately does not need
     * a real user, so an admin can check host, TLS and service credentials before
     * anyone tries to sign in.
     *
     * @return void
     *
     * @throws Exception when the directory cannot be reached or the service bind fails.
     */
    public function verify(): void
    {
        $client = $this->connect();

        try {
            $this->bindService($client);
        } finally {
            $client->unbind();
        }
    }

    /**
     * @return LdapClient
     */
    private function connect(): LdapClient
    {
        return new LdapClient([
            'servers' => $this->settings->getHost(),
            'port' => $this->settings->getPort(),
            'base_dn' => $this->settings->getBaseDn(),
            'use_ssl' => $this->settings->useSsl(),
            'timeout_connect' => self::TIMEOUT_CONNECT,
            'timeout_read' => self::TIMEOUT_OPERATION,
        ]);
    }

    /**
     * Bind as the service account used to search for users.
     *
     * @param LdapClient $client
     *
     * @return void
     */
    private function bindService(LdapClient $client): void
    {
        try {
            if ($this->settings->useStartTls()) {
                $client->startTls();
            }

            // An empty bind DN means the directory allows anonymous search.
            if ($this->settings->getBindDn() !== '') {
                $client->bind($this->settings->getBindDn(), $this->settings->getBindPassword());
            }
        } catch (BindException $error) {
            throw new Exception('Could not authenticate with the LDAP service account. Check the bind DN and password.', AppwriteException::GENERAL_ARGUMENT_INVALID, $error);
        } catch (\Throwable $error) {
            throw new Exception('Could not reach the LDAP server. Check the host, port and encryption settings.', AppwriteException::GENERAL_SERVER_ERROR, $error);
        }
    }

    /**
     * Find the single entry matching the user filter, and the provisioning
     * filter when one is configured.
     *
     * @param LdapClient $client
     * @param string $username
     *
     * @return array{dn: string, email: string, name: string}|null
     */
    private function findEntry(LdapClient $client, string $username): ?array
    {
        $emailAttribute = $this->settings->getEmailAttribute();
        $nameAttribute = $this->settings->getNameAttribute();

        try {
            $entries = $client->search(Operations::search(
                Filters::raw($this->settings->getUserFilter($username)),
                $emailAttribute,
                $nameAttribute
            ));
        } catch (\Throwable $error) {
            throw new Exception('Could not search the LDAP directory. Check the base DN and user filter.', AppwriteException::GENERAL_SERVER_ERROR, $error);
        }

        // More than one match means the filter is not specific enough. Binding
        // as an arbitrary one of them would be a coin toss over identity.
        if (\count($entries) !== 1) {
            return null;
        }

        $entry = $entries->first();

        if ($this->settings->hasProvisionFilter() && !$this->matchesProvisionFilter($client, $username)) {
            return null;
        }

        return [
            'dn' => (string)$entry->getDn(),
            'email' => (string)($entry->get($emailAttribute) ?? ''),
            'name' => (string)($entry->get($nameAttribute) ?? ''),
        ];
    }

    /**
     * Whether the user also satisfies the provisioning restriction, typically a
     * group membership.
     *
     * Evaluated on every sign-in rather than only at first sign-in, so removing
     * someone from the group in the directory revokes their access rather than
     * only preventing a new account.
     *
     * @param LdapClient $client
     * @param string $username
     *
     * @return bool
     */
    private function matchesProvisionFilter(LdapClient $client, string $username): bool
    {
        try {
            $entries = $client->search(Operations::search(
                Filters::raw($this->settings->getProvisionFilter($username))
            ));
        } catch (\Throwable $error) {
            throw new Exception('Could not evaluate the LDAP provisioning filter.', AppwriteException::GENERAL_SERVER_ERROR, $error);
        }

        return \count($entries) > 0;
    }

    /**
     * Attempt to bind as the user. Success is authentication.
     *
     * A fresh connection is used: the service account's bind is still active on
     * the search connection, and rebinding it would break subsequent lookups.
     *
     * @param string $dn
     * @param string $password
     *
     * @return bool
     */
    private function bindUser(string $dn, string $password): bool
    {
        $client = $this->connect();

        try {
            if ($this->settings->useStartTls()) {
                $client->startTls();
            }

            $client->bind($dn, $password);

            return true;
        } catch (BindException) {
            // Wrong password. A normal outcome, not an error.
            return false;
        } catch (\Throwable $error) {
            throw new Exception('Could not complete the LDAP bind.', AppwriteException::GENERAL_SERVER_ERROR, $error);
        } finally {
            $client->unbind();
        }
    }
}
