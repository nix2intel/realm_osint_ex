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

  @username "username@"
  @base_url "https://login.microsoftonline.com/getuserrealm.srf"

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
  def get_realm(domain) when is_binary(domain) do
    login = @username <> domain
    login_encoded = URI.encode(login)
    url = "#{@base_url}?login=#{login_encoded}&json=1"
    Logger.info("Fetching realm information for #{login}")

    case Req.get(url) do
      {:ok, %Req.Response{status: 200, body: body}} ->
        parse_response(body)

      {:ok, %Req.Response{status: status}} ->
        Logger.error("Unexpected HTTP status code: #{status}")
        {:error, :unexpected_status_code}

      {:error, error} ->
        Logger.error("HTTP request failed: #{inspect(error)}")
        {:error, error}
    end
  end

  defp parse_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, result} when is_map(result) ->
        {:ok, result}

      {:error, error} ->
        Logger.error("Failed to decode JSON: #{inspect(error)}")
        {:error, :invalid_json}
    end
  end

  # If the body is already a map, return it directly.
  defp parse_response(body) when is_map(body) do
    {:ok, body}
  end
end
