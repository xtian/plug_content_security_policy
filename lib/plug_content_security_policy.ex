defmodule PlugContentSecurityPolicy do
  import Plug.Conn

  @behaviour Plug

  @moduledoc false

  @directives Application.get_env(:plug_content_security_policy, :directives, %{
    default_src: ~w('none'),
    connect_src: ~w('self'),
    child_src: ~w('self'),
    img_src: ~w('self'),
    script_src: ~w('self'),
    style_src: ~w('self')
  })

  def init([]), do: init(@directives)
  def init(options) do
    Enum.map_join(options, "; ", &convert_tuple/1) <> ";"
  end

  def call(conn, value) do
    put_resp_header(conn, "content-security-policy", value)
  end

  defp convert_tuple({k, v}) when is_atom(k), do: convert_tuple({Atom.to_string(k), v})
  defp convert_tuple({k, v}) when is_binary(v), do: convert_tuple({k, [v]})
  defp convert_tuple({k, v}) do
    key = String.replace(k, "_", "-")
    values = Enum.map_join(v, " ", &("'#{&1}'"))
    "#{key} #{values}"
  end

end
