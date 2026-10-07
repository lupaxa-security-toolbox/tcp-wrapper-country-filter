<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Tcp Wrapper Country Filter</h1>

TCP Wrapper filter that the [Tcp Wrapper Multiplexer](https://github.com/lupaxa-security-toolbox/tcp-wrapper-multiplexer) can run.
It checks one client address and exits `0` to allow the connection. Any other exit code denies it, and the multiplexer stops on that result.

> **Note:**
> TCP Wrappers do not replace a firewall. Use this filter as one layer of a larger control.

## Install

Copy `src/country-filter.py` to `/usr/local/sbin/country-filter` and make it executable:

```bash
sudo install -m 755 src/country-filter.py /usr/local/sbin/country-filter
```

`src/country-filter.py --version` prints the filter version. A deny log includes that same version.

The filter reads the IPinfo Lite MMDB that [IPinfo Update](https://github.com/lupaxa-security-toolbox/ipinfo-update) downloads. Install `maxminddb` for the Python that runs the script:

```bash
python3 -m pip install maxminddb
```

`DATABASE` is `/var/lib/ipinfo/ipinfo_lite.mmdb`, the same path `ipinfo-update` writes by default. TCP Wrappers do not run the filter from the directory that holds the file, so keep that path absolute.

## Configure the Check

`ACTION` is `DENY` or `ALLOW`.

- `DENY` blocks a value that matches the list.
- `ALLOW` blocks a value that does not match the list.

`check_results` exits `1` on deny. Allow falls through, and `main` exits `0`.

Set `DATABASE`, `BAN_LIST`, and `ACTION` at the top of `src/country-filter.py`. `BAN_LIST` holds two-letter country codes. `lookup` reads `country_code` from the IPinfo Lite record:

```python
DATABASE = Path("/var/lib/ipinfo/ipinfo_lite.mmdb")
BAN_LIST = "CN RU"
ACTION = DENY_ACTION
```

An address with no country code, an invalid address, or a missing database makes `lookup` return an empty string. `DENY` then allows that connection. `ALLOW` blocks it.

## Multiplexer

The multiplexer does not decide allow or deny itself. It runs each named filter and returns the first deny.

Set `FILTERS` in the multiplexer to `country-filter`. Filters run from `FILTER_PATH` (default `/usr/local/sbin`).

```bash
FILTERS="country-filter"
FILTER_PATH="/usr/local/sbin"
```

The filter is called as:

```bash
/usr/local/sbin/country-filter <client-ip> MUX
```

The second argument sets `MUX`, so `in_multiplexer` is true and `debug` prints as well as logging.

## TCP Wrapper Order

TCP Wrappers read `/etc/hosts.allow` first, then `/etc/hosts.deny`. Anything not handled in `hosts.allow` falls through to `hosts.deny`.

When the multiplexer is in front, `hosts.allow` calls the multiplexer, not this filter. Use the rules below only when this filter runs on its own.

### Hosts Allow

Pass every SSH client address to the filter. `aclexec` runs the script, and `%a` is the client address. Exit `0` allows the connection. Exit `1` denies it.

```text
sshd: ALL: aclexec /usr/local/sbin/country-filter %a
```

### Hosts Deny

Deny SSH when `hosts.allow` does not allow it:

```text
sshd: ALL
```

> **Note:**
> The deny rule should not be reached when the filter handles every address. Keep it as a fallback.

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
