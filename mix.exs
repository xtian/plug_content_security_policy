defmodule PlugContentSecurityPolicy.Mixfile do
  use Mix.Project

  @github_url "https://github.com/xtian/plug_content_security_policy"
  @version "0.1.1"

  def project do
    [
      app: :plug_content_security_policy,
      version: @version,
      elixir: "~> 1.3",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Hex
      description: description(),
      package: package(),

      # Docs
      name: "PlugContentSecurityPolicy",
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_ref: "v#{@version}",
        source_url: @github_url
      ],
      dialyzer: [
        flags: [
          :error_handling,
          :race_conditions,
          :unmatched_returns
        ],
        ignore_warnings: "config/dialyzer_ignore.exs"
      ]
    ]
  end

  def application do
    [applications: [:logger, :plug]]
  end

  defp deps do
    [
      {:credo, "~> 1.1", only: [:dev, :test]},
      {:credo_contrib, "~> 0.1", only: [:dev, :test]},
      {:dialyxir, "~> 1.0-rc", only: [:dev, :test]},
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:plug, "~> 1.3"}
    ]
  end

  def description do
    """
    A Plug module for inserting a Content Security Policy header into the
    response. Supports generating nonces as specified in CSP Level 2.
    """
  end

  def package do
    [
      maintainers: ["Christian Wesselhoeft"],
      licenses: ["ISC"],
      links: %{"GitHub" => @github_url}
    ]
  end
end
