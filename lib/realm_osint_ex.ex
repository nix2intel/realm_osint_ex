defmodule RealmOsintEx do
  @moduledoc """
  RealmOsintEx is an OSINT tool built with Elixir for querying Microsoft's GetUserRealm endpoint using Req.

  This library uses a fixed username prefix (`"username@"`) so that callers only need to supply a domain (e.g., `"example.com"`).
  The full login is then constructed as `"username@example.com"`.

  The JSON response from the endpoint varies based on the domain’s configuration.

  **For a Federated Domain**, the response may include:

    - `"State"`: integer status (e.g., 3, meaning federated).
    - `"UserState"`: integer providing additional context.
    - `"Login"`: full user login (e.g., `"username@example.com"`).
    - `"NameSpaceType"`: typically `"Federated"`.
    - `"DomainName"`: the domain (e.g., `"example.com"`).
    - `"FederationGlobalVersion"`: integer version (often `-1`).
    - `"AuthURL"`: URL to redirect for federated authentication.
    - `"FederationBrandName"`: the identity provider's brand.
    - `"AuthNForwardType"`: an integer indicating the authentication forwarding type.
    - `"CloudInstanceName"`: usually `"microsoftonline.com"`.
    - `"CloudInstanceIssuerUri"`: the issuer URI for the cloud instance.

  **For an Unknown Domain**, the response may only include:

    - `"State"`: an integer (e.g., 4, meaning non-federated).
    - `"UserState"`: integer providing additional context.
    - `"Login"`: the constructed login.
    - `"NameSpaceType"`: typically `"Unknown"`.

  This tool empowers OSINT investigations by quickly identifying a domain's authentication configuration.
  """

  require Logger
  require Record

  Record.defrecordp(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecordp(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  defp parse_xml(xml_string) do
    {doc, _} =
      xml_string
      |> String.to_charlist()
      |> :xmerl_scan.string()

    get_text = fn xpath ->
      element = hd(:xmerl_xpath.string(String.to_charlist(xpath), doc))
      [xmlText(value: value)] = :xmerl_xpath.string(~c"./text()", element)
      to_string(value)
    end

    %{
      "State" => get_text.("/RealmInfo/State"),
      "UserState" => get_text.("/RealmInfo/UserState"),
      "Login" => get_text.("/RealmInfo/Login"),
      "NameSpaceType" => get_text.("/RealmInfo/NameSpaceType"),
      "DomainName" => get_text.("/RealmInfo/DomainName"),
      "FederationGlobalVersion" => get_text.("/RealmInfo/FederationGlobalVersion"),
      "AuthURL" => get_text.("/RealmInfo/AuthURL"),
      "IsFederatedNS" => get_text.("/RealmInfo/IsFederatedNS"),
      "STSAuthURL" => get_text.("/RealmInfo/STSAuthURL"),
      "FederationTier" => get_text.("/RealmInfo/FederationTier"),
      "FederationBrandName" => get_text.("/RealmInfo/FederationBrandName"),
      "AllowFedUsersWLIDSignIn" => get_text.("/RealmInfo/AllowFedUsersWLIDSignIn"),
      "Certificate" => get_text.("/RealmInfo/Certificate"),
      "MEXURL" => get_text.("/RealmInfo/MEXURL"),
      "PreferredProtocol" => get_text.("/RealmInfo/PreferredProtocol"),
      "EDUDomainFlags" => get_text.("/RealmInfo/EDUDomainFlags"),
      "CloudInstanceName" => get_text.("/RealmInfo/CloudInstanceName"),
      "CloudInstanceIssuerUri" => get_text.("/RealmInfo/CloudInstanceIssuerUri")
    }
  end

  @doc """
  Retrieves user realm information for a given domain using Req.

  A fixed username prefix of `"username@"` is used to build the login,
  so you only need to pass the domain (e.g., `"example.com"`).

  ## Parameters

    - domain: A string representing the domain (e.g., `"example.com"`).

  ## Returns

    - `{:ok, map}` with keys such as:
        - `"State"`: integer
        - `"UserState"`: integer
        - `"Login"`: string (e.g., `"username@example.com"`)
        - `"NameSpaceType"`: string
        - `"DomainName"`: string (if provided)
        - `"FederationGlobalVersion"`: integer (if provided)
        - `"AuthURL"`: string (if provided)
        - `"FederationBrandName"`: string (if provided)
        - `"AuthNForwardType"`: integer (if provided)
        - `"CloudInstanceName"`: string (if provided)
        - `"CloudInstanceIssuerUri"`: string (if provided)

    - `{:error, reason}` if the HTTP request or JSON processing fails.
  """
  def get_realm(domain, format \\ :xml) when is_binary(domain) do
    Req.new(
      method: :get,
      base_url: "https://login.microsoftonline.com/getuserrealm.srf",
      params:
        %{
          login: "username@#{domain}"
        }
        |> Map.merge(
          case format do
            :json -> %{json: 1}
            :xml -> %{xml: 1}
          end
        )
    )
    |> Req.request()
    |> case do
      {:ok,
       %Req.Response{
         status: 200,
         headers: %{"content-type" => ["application/json" <> _]},
         body: body
       }} ->
        {:ok, body}

      {:ok,
       %Req.Response{status: 200, headers: %{"content-type" => ["text/xml" <> _]}, body: body}} ->
        {:ok, parse_xml(body)}

      {:ok, %Req.Response{status: status}} when status != 200 ->
        Logger.error("Unexpected HTTP status code: #{status}")
        {:error, :unexpected_status_code}

      {:error, error} ->
        Logger.error("HTTP request failed: #{inspect(error)}")
        {:error, error}
    end
  end
end
