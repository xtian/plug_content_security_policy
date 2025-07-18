defmodule PlugContentSecurityPolicy do
  @moduledoc """
  A Plug module for inserting a Content Security Policy header into the
  response. Supports generating nonces as specified in CSP Level 2.
  """

  @behaviour Plug

  alias Plug.Conn

  require Logger

  @app_name :plug_content_security_policy

  @default_field "content-security-policy"
  @report_field "content-security-policy-report-only"

  @doc """
  Accepts the following options:

  - `:directives`: Map of CSP directives with values as lists of strings
  - `:nonces_for`: List of CSP directive keys for which to generate nonces
    (valid keys: `:script_src`, `:style_src`)
  - `:report_only`: Set `#{@report_field}` header instead of `#{@default_field}`

  See [README](./readme.html#usage) for usage details.
  """

  @spec init(Plug.opts()) :: Plug.opts()
  def init(config) when is_list(config) do
    config |> Map.new() |> init()
  end

  def init(%{} = config) do
    case Map.merge(default_config(), config) do
      %{nonces_for: [_ | _]} = config -> config
      config -> build_header(config)
    end
  end

  def init(_) do
    _ = Logger.warning("#{__MODULE__}: Invalid config, using defaults")
    init(%{})
  end

  @spec call(Conn.t(), Plug.opts()) :: Conn.t()
  def call(conn, {field_name, value}) when field_name in [@default_field, @report_field] do
    Conn.put_resp_header(conn, field_name, value)
  end

  def call(conn, %{} = config) do
    {conn, directives} = insert_nonces(conn, config.directives, config.nonces_for)
    call(conn, build_header(%{config | directives: directives}))
  end

  defp build_header(config) do
    field_value = Enum.map_join(config.directives, "; ", &convert_tuple/1) <> ";"

    if config.report_only do
      _ =
        unless config.directives[:report_uri] do
          Logger.warning("#{__MODULE__}: `report_only` enabled but no `report_uri` specified")
        end

      {@report_field, field_value}
    else
      {@default_field, field_value}
    end
  end

  defp convert_tuple({key, value}) do
    key = key |> to_string() |> String.replace("_", "-")
    value = value |> List.wrap() |> Enum.join(" ")

    "#{key} #{value}"
  end

  defp default_config do
    %{
      nonces_for: Application.get_env(@app_name, :nonces_for, []),
      report_only: Application.get_env(@app_name, :report_only, false),
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
    32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  @valid_nonces_for [:script_src, :style_src]

  defp insert_nonces(conn, directives, []) do
    {conn, directives}
  end

  defp insert_nonces(conn, directives, [key | nonces_for]) when key in @valid_nonces_for do
    nonce = generate_nonce()
    nonce_attr = "'nonce-#{nonce}'"
    directives = Map.update(directives, key, [nonce_attr], &[nonce_attr | &1])

    conn
    |> Conn.assign(:"#{key}_nonce", nonce)
    |> insert_nonces(directives, nonces_for)
  end

  defp insert_nonces(conn, directives, [key | nonces_for]) do
    _ = Logger.warning("#{__MODULE__}: Invalid `nonces_for` value: #{inspect(key)}")
    insert_nonces(conn, directives, nonces_for)
  end
end
