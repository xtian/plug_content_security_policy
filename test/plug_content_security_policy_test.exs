defmodule PlugContentSecurityPolicyTest do
  use ExUnit.Case, async: true
  use Plug.Test

  describe ".init/1" do
    test "returns a CSP directive" do
      options = %{
        default_src: "none",
        script_src: ~w(self unsafe-inline)
      }

      directive = PlugContentSecurityPolicy.init(options)
      assert directive == "default-src 'none'; script-src 'self' 'unsafe-inline';"
    end
  end

  describe ".call/2" do
    test "sets the CSP header" do
      conn =
        :get
        |> conn("/")
        |> PlugContentSecurityPolicy.call("default-src 'none';")

      assert get_resp_header(conn, "content-security-policy") == ["default-src 'none';"]
    end
  end
end
