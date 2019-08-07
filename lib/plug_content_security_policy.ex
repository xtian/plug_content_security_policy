defmodule PlugContentSecurityPolicy do
  @moduledoc """
  A Plug module for inserting a Content Security Policy header into the
  response. Supports generating nonces as specified in CSP Level 2.
  """

  @behaviour Plug

  alias Plug.Conn

  @app_name :plug_content_security_policy

  @doc """
  Accepts the following options:

  - `:directives`: Map of CSP directives with values as lists of strings
  - `:nonces_for`: List of CSP directive keys to generate nonces for
  - `:report_only`: Use the `content-security-policy-report-only` header
    instead of the `content-security-policy` header.

  See [README](./readme.html#usage) for usage details.
  """

  @spec init(Plug.opts()) :: Plug.opts()
  def init([]), do: init(default_config())

  def init(config) when is_list(config), do: init(Map.new(config))

  def init(%{} = config) do
    if needs_nonce?(config) do
      config
    else
      {header(config), build_header(config)}
    end
  end

  @spec call(Conn.t(), Plug.opts()) :: Conn.t()
  def call(conn, value) when is_binary(value) do
    Conn.put_resp_header(conn, "content-security-policy", value)
  end

  def call(conn, config) do
    directives = config[:directives] || %{}
    nonces_for = config[:nonces_for] || []
    {conn, directives} = insert_nonces(conn, directives, nonces_for)

    call(conn, build_header(directives))
  end

  defp build_header(%{directives: directives}), do: build_header(directives)
  defp build_header(map), do: Enum.map_join(map, "; ", &convert_tuple/1) <> ";"

  defp convert_tuple({k, v}) when is_atom(k), do: convert_tuple({Atom.to_string(k), v})
  defp convert_tuple({k, v}) when not is_list(v), do: convert_tuple({k, [v]})

  defp convert_tuple({k, v}) do
    v = Enum.reject(v, &is_nil/1)
    "#{String.replace(k, "_", "-")} #{Enum.map_join(v, " ", &convert_value/1)}"
  end

  defp convert_value(v) when is_atom(v), do: "'#{v}'"
  defp convert_value(v), do: v

  defp default_config do
    %{
      nonces_for: Application.get_env(@app_name, :nonces_for),
      directives:
        Application.get_env(@app_name, :directives, %{
          default_src: ~w('none'),
          connect_src: ~w('self'),
          child_src: ~w('self'),
          img_src: ~w('self'),
          script_src: ~w('self'),
          style_src: ~w('self')
        })
    }
  end

  defp generate_nonce, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  defp insert_nonces(conn, directives, []), do: {conn, directives}

  defp insert_nonces(conn, directives, [key | nonces_for]) do
    nonce = generate_nonce()
    nonce_attr = "'nonce-#{nonce}'"
    directives = Map.update(directives, key, [nonce_attr], &[nonce_attr | &1])

    conn
    |> Conn.assign(:"#{key}_nonce", nonce)
    |> insert_nonces(directives, nonces_for)
  end

  defp needs_nonce?(%{nonces_for: [_ | _]}), do: true
  defp needs_nonce?(_), do: false

  defp header(%{report_only: true}), do: "content-security-policy-report-only"
  defp header(_), do: "content-security-policy"
end
