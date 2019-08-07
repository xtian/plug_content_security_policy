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

  See [README](./readme.html#usage) for usage details.
  """
  @spec init(Plug.opts()) :: Plug.opts()
  def init([]) do
    init(default_config())
  end

  def init(config) do
    if needs_nonce?(config) do
      config
    else
      build_header(config[:directives])
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

  defp build_header(map) do
    Enum.map_join(map, "; ", &convert_tuple/1) <> ";"
  end

  defp convert_tuple({k, v}) when is_atom(k), do: convert_tuple({Atom.to_string(k), v})
  defp convert_tuple({k, v}), do: "#{String.replace(k, "_", "-")} #{Enum.join(v, " ")}"

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

  defp generate_nonce do
    32 |> :crypto.strong_rand_bytes() |> Base.encode64()
  end

  defp insert_nonces(conn, directives, []) do
    {conn, directives}
  end

  defp insert_nonces(conn, directives, [key | nonces_for]) do
    nonce = generate_nonce()
    nonce_attr = "'nonce-#{nonce}'"
    directives = Map.update(directives, key, [nonce_attr], &[nonce_attr | &1])

    conn |> Conn.assign(:"#{key}_nonce", nonce) |> insert_nonces(directives, nonces_for)
  end

  defp needs_nonce?(%{nonces_for: [_ | _]}), do: true
  defp needs_nonce?(_), do: false
end
