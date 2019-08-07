defmodule PlugContentSecurityPolicyTest do
  use ExUnit.Case, async: true
  use Plug.Test

  setup do
    {:ok, conn: conn(:get, "/")}
  end

  describe ".init/1" do
    test "pre-builds CSP directive if possible" do
      directives = %{
        default_src: ~w('none'),
        script_src: ~w('self' 'unsafe-inline')
      }

      directive = PlugContentSecurityPolicy.init(directives: directives)

      assert directive ==
               {"content-security-policy",
                "default-src 'none'; script-src 'self' 'unsafe-inline';"}

      directive = PlugContentSecurityPolicy.init(directives: directives, report_only: true)

      assert directive ==
               {"content-security-policy-report-only",
                "default-src 'none'; script-src 'self' 'unsafe-inline';"}
    end

    test "merges defaults with provided config" do
      config = %{nonces_for: [:script_src]}
      new_config = PlugContentSecurityPolicy.init(config)

      assert new_config.nonces_for == config.nonces_for
      assert new_config.directives
    end
  end

  describe ".call/2" do
    test "sets the CSP header if pre-generated", %{conn: conn} do
      opts = PlugContentSecurityPolicy.init(directives: %{default_src: ~w('none')})
      conn = PlugContentSecurityPolicy.call(conn, opts)

      assert get_resp_header(conn, "content-security-policy") == ["default-src 'none';"]
      refute conn.assigns[:script_src_nonce]
      refute conn.assigns[:style_src_nonce]
    end

    test "generates nonces if required", %{conn: conn} do
      conn =
        PlugContentSecurityPolicy.call(
          conn,
          %{
            directives: %{script_src: ~w('none')},
            nonces_for: [:script_src, :style_src],
            report_only: false
          }
        )

      [header] = get_resp_header(conn, "content-security-policy")

      assert header =~ "script-src 'nonce-#{conn.assigns.script_src_nonce}' 'none';"
      assert header =~ "style-src 'nonce-#{conn.assigns.style_src_nonce}';"
    end

    test "only assigns required nonce", %{conn: conn} do
      conn = PlugContentSecurityPolicy.call(conn, %{directives: %{}, nonces_for: [:style_src], report_only: false})

      refute conn.assigns[:script_src_nonce]
    end
  end
end
