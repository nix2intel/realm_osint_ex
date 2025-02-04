defmodule RealmOsintEx do
  import SweetXml

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

  def parse_xml(xml_string) do
    # Parse the XML string
    doc = SweetXml.parse(xml_string)

    %{
      "State" => xpath(doc, ~x"/RealmInfo/State/text()"s),
      "UserState" => xpath(doc, ~x"/RealmInfo/UserState/text()"s),
      "Login" => xpath(doc, ~x"/RealmInfo/Login/text()"s),
      "NameSpaceType" => xpath(doc, ~x"/RealmInfo/NameSpaceType/text()"s),
      "DomainName" => xpath(doc, ~x"/RealmInfo/DomainName/text()"s),
      "FederationGlobalVersion" => xpath(doc, ~x"/RealmInfo/FederationGlobalVersion/text()"s),
      "AuthURL" => xpath(doc, ~x"/RealmInfo/AuthURL/text()"s),
      "IsFederatedNS" => xpath(doc, ~x"/RealmInfo/IsFederatedNS/text()"s),
      "STSAuthURL" => xpath(doc, ~x"/RealmInfo/STSAuthURL/text()"s),
      "FederationTier" => xpath(doc, ~x"/RealmInfo/FederationTier/text()"s),
      "FederationBrandName" => xpath(doc, ~x"/RealmInfo/FederationBrandName/text()"s),
      "AllowFedUsersWLIDSignIn" => xpath(doc, ~x"/RealmInfo/AllowFedUsersWLIDSignIn/text()"s),
      "Certificate" => xpath(doc, ~x"/RealmInfo/Certificate/text()"s),
      "MEXURL" => xpath(doc, ~x"/RealmInfo/MEXURL/text()"s),
      "PreferredProtocol" => xpath(doc, ~x"/RealmInfo/PreferredProtocol/text()"s),
      "EDUDomainFlags" => xpath(doc, ~x"/RealmInfo/EDUDomainFlags/text()"s),
      "CloudInstanceName" => xpath(doc, ~x"/RealmInfo/CloudInstanceName/text()"s),
      "CloudInstanceIssuerUri" => xpath(doc, ~x"/RealmInfo/CloudInstanceIssuerUri/text()"s)
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
  require Logger

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
