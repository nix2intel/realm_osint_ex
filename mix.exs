defmodule RealmOsintEx.MixProject do
  use Mix.Project

  @version "0.2.0"

  @source_url "https://github.com/osintowl/realm_osint_ex"

  def project do
    [
      app: :realm_osint_ex,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "RealmOsintEx",
      source_url: @source_url
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:req, "~> 0.5.8"},
      {:sweet_xml, "~> 0.7.5"},
      {:ex_doc, "~> 0.35.1", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "realm_osint_ex",
      files: ~w(lib .formatter.exs mix.exs README* LICENSE*),
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      extras: ["README.md"]
    ]
  end

  defp description do
    """
    RealmOsintEx is an Elixir library that simplifies OSINT investigations by querying Microsoft's GetUserRealm endpoint. It automatically constructs a standardized login and returns the domain's authentication configuration, providing a seamless way to ascertain how a domain handles authentication.
    """
  end
end
