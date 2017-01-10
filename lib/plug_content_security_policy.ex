defmodule PlugContentSecurityPolicy do
  import Plug.Conn

  @behaviour Plug

  @moduledoc false

  @nonces_for Application.get_env(:plug_content_security_policy, :nonces_for)
  @directives Application.get_env(:plug_content_security_policy, :directives, %{
    default_src: ~w('none'),
    connect_src: ~w('self'),
    child_src: ~w('self'),
    img_src: ~w('self'),
    script_src: ~w('self'),
    style_src: ~w('self')
  })

  @spec init(map | keyword) :: String.t | map | keyword
  def init([]), do: init(%{directives: @directives, nonces_for: @nonces_for})
  def init(config) do
    if needs_nonce?(config), do: config, else: build_header(config.directives)
  end

  @spec call(Plug.Conn.t, String.t | map | keyword) :: Plug.Conn.t
  def call(conn, value) when is_binary(value), do: put_resp_header(conn, "content-security-policy", value)
  def call(conn, config) do
    directives = config[:directives] || %{}
    nonces_for = config[:nonces_for] || []
    {conn, directives} = insert_nonces(conn, directives, nonces_for)

    call(conn, build_header(directives))
  end

  defp build_header(map), do: Enum.map_join(map, "; ", &convert_tuple/1) <> ";"

  defp convert_tuple({k, v}) when is_atom(k), do: convert_tuple({Atom.to_string(k), v})
  defp convert_tuple({k, v}), do: "#{String.replace(k, "_", "-")} #{Enum.join(v, " ")}"

  defp generate_nonce, do: 32 |> :crypto.strong_rand_bytes |> Base.encode64

  defp insert_nonces(conn, directives, []), do: {conn, directives}
  defp insert_nonces(conn, directives, [key | nonces_for]) do
    nonce = generate_nonce()
    nonce_attr = "'nonce-#{nonce}'"
    directives = Map.update(directives, key, [nonce_attr], &[nonce_attr | &1])

    insert_nonces(assign(conn, :"#{key}_nonce", nonce), directives, nonces_for)
  end

  defp needs_nonce?(%{nonces_for: [_ | _]}), do: true
  defp needs_nonce?(_), do: false
end
