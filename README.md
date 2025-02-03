
# RealmOsintEx
---

RealmOsintEx is an OSINT tool built with Elixir for querying Microsoft's GetUserRealm endpoint. It enables efficient investigation of a domain’s authentication configuration by constructing a standardized login using a fixed prefix (`"username@"`) and a provided domain.

---

## Overview

When querying Microsoft’s GetUserRealm endpoint, RealmOsintEx returns a map containing various keys that describe the authentication realm of the specified domain. The response structure can vary depending on the domain’s configuration, and you can generally expect one of two types:

- **Federated Domains**  
  These responses contain a rich set of fields that indicate the domain is using federation for authentication. Typical keys include:
  - **"State"**: An integer that represents the domain’s authentication status (commonly `3` for federated domains).
  - **"UserState"**: An integer with additional context (often `2` for federated setups).
  - **"Login"**: A string with the constructed login (e.g., `"username@example.com"`).
  - **"NameSpaceType"**: Typically `"Federated"`.
  - **"DomainName"**: The queried domain (e.g., `"example.com"`).
  - **"AuthNForwardType"**: An integer signaling how authentication requests should be forwarded.
  - **"AuthURL"**: A URL to which authentication requests should be directed.
  - **"FederationBrandName"**: The brand name of the identity provider (for example, a customized provider name).
  - **"FederationGlobalVersion"**: An integer indicating the configuration version (commonly `-1`).
  - **"CloudInstanceName"** and **"CloudInstanceIssuerUri"**: Information on the Microsoft Online instance handling the authentication.

- **Unknown or Managed Domains**  
  For domains that are not federated or use a different type of authentication, the endpoint is likely to return a more limited data set such as:
  - **"State"**: A numerical code (e.g., `4` for non-federated domains).
  - **"UserState"**: Often a basic context indicator (commonly `1`).
  - **"Login"**: The constructed login.
  - **"NameSpaceType"**: Generally reported as `"Unknown"`, reflecting that federated details are not provided.

Each key provides detailed insight into how authentication is handled for the domain, making RealmOsintEx a valuable addition to any OSINT toolkit.

---

## Features

- **Simple Domain Lookup:** Only supply the domain (e.g., `example.com`) and the tool constructs the login (`"username@example.com"`) automatically.
- **OSINT Integration:** Quickly determine if a domain is federated (with detailed configuration) or unknown/managed.
- **Robust HTTP Handling:** Uses the Req library for HTTP requests, with graceful parsing of JSON responses whether in binary form or already decoded.
- **Detailed Authentication Mapping:** Provides insights into authentication redirection, federation branding, and cloud instance configurations.

---

## Installation

Add RealmOsintEx to your Elixir project by updating your `mix.exs` dependencies:

```elixir
defp deps do
  [
    {:req, "~> 0.3.0"},
    {:jason, "~> 1.2"}
  ]
end
```

Then fetch the dependencies:

```bash
mix deps.get
```

---

## Usage

RealmOsintEx makes it easy to query the Microsoft GetUserRealm endpoint. For example, querying for `example.com`:

```elixir
iex> RealmOsintEx.get_realm("example.com")
{:ok,
 %{
   "AuthNForwardType" => 1,
   "AuthURL" =>
     "https://sts.microsoftonline.com/Trust/2005/UsernameMixed?username=username%40example.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=",
   "CloudInstanceIssuerUri" => "urn:federation:MicrosoftOnline",
   "CloudInstanceName" => "microsoftonline.com",
   "DomainName" => "example.com",
   "FederationBrandName" => "test_test_06102020MM",
   "FederationGlobalVersion" => -1,
   "Login" => "username@example.com",
   "NameSpaceType" => "Federated",
   "State" => 3,
   "UserState" => 2
 }}
```

For unknown or managed domains, the returned map will mainly include minimal keys like `"State"`, `"UserState"`, `"Login"`, and `"NameSpaceType"` (typically set to `"Unknown"`).

---

## Building and Running

1. **Create a New Project** (if you haven't already):

   ```bash
   mix new realm_osint_ex
   ```

2. **Navigate into the Project Directory:**

   ```bash
   cd realm_osint_ex
   ```

3. **Add and Fetch Dependencies:**

   Update your `mix.exs` and run:

   ```bash
   mix deps.get
   ```

4. **Compile the Project:**

   ```bash
   mix compile
   ```

5. **Start an Interactive Shell (IEx):**

   ```bash
   iex -S mix
   ```

6. **Test the Module:**

   At the IEx prompt, run:

   ```elixir
   RealmOsintEx.get_realm("example.com")
   ```

If needed, you can build a release using:

```bash
mix release
```

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests if you find bugs, have feature requests, or would like to help improve RealmOsintEx.

---

## License

RealmOsintEx is released under the BSD 3-Clause License. This license permits redistribution and use in source and binary forms, with or without modification, as long as the following conditions are met:

- Redistributions of source code must retain the BSD 3-clause license notice.
- Redistributions in binary form must reproduce the BSD 3-clause license notice in the documentation and/or other materials provided with the distribution.
- Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

See the LICENSE file for the full text of the license.

---

RealmOsintEx provides a straightforward and efficient approach to integrating Microsoft's authentication realm discovery into your OSINT workflows. Enjoy exploring, investigating, and enhancing your domain intelligence capabilities with RealmOsintEx!
