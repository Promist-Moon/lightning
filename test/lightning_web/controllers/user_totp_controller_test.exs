defmodule LightningWeb.UserTOTPControllerTest do
  use LightningWeb.ConnCase, async: false

  import Lightning.Factories
  import Mock

  alias Lightning.TotpRateLimit

  @totp_session :user_totp_pending
  @two_factor_bucket "two_factor_verification"
  @two_factor_limit 5
  @two_factor_window :timer.minutes(15)

  setup %{conn: conn} do
    user =
      insert(:user,
        mfa_enabled: true,
        user_totp: build(:user_totp),
        backup_codes: build_list(10, :backup_code)
      )

    conn = conn |> log_in_user(user) |> put_session(@totp_session, true)
    %{user: user, conn: conn}
  end

  describe "GET /users/two-factor" do
    test "renders totp page by default", %{conn: conn} do
      conn = get(conn, Routes.user_totp_path(conn, :new))
      response = html_response(conn, 200)
      assert response =~ "Two-factor authentication"

      assert response =~
               "Open your two-factor authenticator (TOTP) app or browser extension to view your authentication code"

      refute response =~ "Use one of your backup codes"
    end

    test "renders backup code page by default", %{conn: conn} do
      conn =
        get(
          conn,
          Routes.user_totp_path(conn, :new, authentication_type: "backup_code")
        )

      response = html_response(conn, 200)
      assert response =~ "Two-factor authentication"

      refute response =~
               "Open your two-factor authenticator (TOTP) app or browser extension to view your authentication code"

      assert response =~ "Use one of your backup codes"
    end

    test "reads remember me from URL", %{conn: conn} do
      conn =
        get(conn, Routes.user_totp_path(conn, :new), user: [remember_me: "true"])

      response = html_response(conn, 200) |> Floki.parse_document!()

      assert Floki.find(
               response,
               ~s|input#user_remember_me[name="user[remember_me]"][type="hidden"][value="true"]|
             )
    end

    test "redirects to login if not logged in" do
      conn = build_conn()

      assert conn
             |> get(Routes.user_totp_path(conn, :new))
             |> redirected_to() ==
               Routes.user_session_path(conn, :new)
    end

    test "redirects to dashboard if totp is not pending", %{conn: conn} do
      assert conn
             |> delete_session(@totp_session)
             |> get(Routes.user_totp_path(conn, :new))
             |> redirected_to() == "/projects"
    end
  end

  describe "POST /users/two-factor using app" do
    test "validates totp correctly", %{conn: conn, user: user} do
      code = NimbleTOTP.verification_code(user.user_totp.secret)

      conn =
        post(conn, Routes.user_totp_path(conn, :create), %{
          "user" => %{"code" => code, "authentication_type" => "totp"}
        })

      assert redirected_to(conn) == "/projects"
      assert get_session(conn, @totp_session) == nil
    end

    test "logs the user in with remember me", %{conn: conn, user: user} do
      code = NimbleTOTP.verification_code(user.user_totp.secret)

      conn =
        post(conn, Routes.user_totp_path(conn, :create), %{
          "user" => %{
            "code" => code,
            "authentication_type" => "totp",
            "remember_me" => "true"
          }
        })

      assert redirected_to(conn) == "/projects"
      assert get_session(conn, @totp_session) == nil
      assert conn.resp_cookies["_lightning_web_user_remember_me"]
    end

    test "logs the user in with return to", %{conn: conn, user: user} do
      code = NimbleTOTP.verification_code(user.user_totp.secret)

      conn =
        conn
        |> put_session(:user_return_to, "/return_here")
        |> post(Routes.user_totp_path(conn, :create), %{
          "user" => %{"code" => code, "authentication_type" => "totp"}
        })

      assert redirected_to(conn) == "/return_here"
      assert get_session(conn, @totp_session) == nil
    end

    test "returns the generic invalid message when rate limited", %{
      conn: conn,
      user: user
    } do
      code = NimbleTOTP.verification_code(user.user_totp.secret)

      with_mock(Lightning.TotpRateLimit, [:passthrough],
        hit: fn _, _, _ ->
          {:deny, 5}
        end
      ) do
        conn =
          post(conn, Routes.user_totp_path(conn, :create), %{
            "user" => %{"code" => code, "authentication_type" => "totp"}
          })

        response = html_response(conn, 200)
        assert response =~ "Invalid two-factor authentication code"
        refute get_session(conn, @totp_session) == nil
      end
    end

    test "fails closed when the limiter is unavailable", %{
      conn: conn,
      user: user
    } do
      code = NimbleTOTP.verification_code(user.user_totp.secret)

      with_mock(Lightning.TotpRateLimit, [:passthrough],
        hit: fn _, _, _ ->
          raise "backend unavailable"
        end
      ) do
        conn =
          post(conn, Routes.user_totp_path(conn, :create), %{
            "user" => %{"code" => code, "authentication_type" => "totp"}
          })

        response = html_response(conn, 200)
        assert response =~ "Invalid two-factor authentication code"
        refute get_session(conn, @totp_session) == nil
      end
    end

    test "allows N failed attempts and refuses N+1 even with a correct code", %{
      conn: conn,
      user: user
    } do
      conn_after_failures =
        Enum.reduce(1..@two_factor_limit, conn, fn _, acc ->
          attempt_conn =
            post(acc, Routes.user_totp_path(acc, :create), %{
              "user" => %{
                "code" => "000000",
                "authentication_type" => "totp"
              }
            })

          assert html_response(attempt_conn, 200) =~
                   "Invalid two-factor authentication code"

          refute get_session(attempt_conn, @totp_session) == nil
          attempt_conn
        end)

      valid_code = NimbleTOTP.verification_code(user.user_totp.secret)

      denied_conn =
        post(
          conn_after_failures,
          Routes.user_totp_path(conn_after_failures, :create),
          %{
            "user" => %{
              "code" => valid_code,
              "authentication_type" => "totp"
            }
          }
        )

      assert html_response(denied_conn, 200) =~
               "Invalid two-factor authentication code"

      refute get_session(denied_conn, @totp_session) == nil
    end

    test "rate limit bucket is isolated per account", %{conn: conn, user: user_a} do
      exhausted_conn =
        Enum.reduce(1..(@two_factor_limit + 1), conn, fn _, acc ->
          post(acc, Routes.user_totp_path(acc, :create), %{
            "user" => %{
              "code" => "000000",
              "authentication_type" => "totp"
            }
          })
        end)

      assert html_response(exhausted_conn, 200) =~
               "Invalid two-factor authentication code"

      user_b =
        insert(:user,
          mfa_enabled: true,
          user_totp: build(:user_totp),
          backup_codes: build_list(10, :backup_code)
        )

      user_b_conn =
        build_conn()
        |> log_in_user(user_b)
        |> put_session(@totp_session, true)

      user_b_valid_code = NimbleTOTP.verification_code(user_b.user_totp.secret)

      allowed_conn =
        post(user_b_conn, Routes.user_totp_path(user_b_conn, :create), %{
          "user" => %{
            "code" => user_b_valid_code,
            "authentication_type" => "totp"
          }
        })

      assert redirected_to(allowed_conn) == "/projects"
      assert get_session(allowed_conn, @totp_session) == nil

      # Explicitly verify the exhausted bucket belongs to user A only.
      assert TotpRateLimit.get(bucket_for(user_a), @two_factor_window) >
               TotpRateLimit.get(bucket_for(user_b), @two_factor_window)
    end

    test "rate limit window expires", %{user: user} do
      key = bucket_for(user)
      window = 100

      assert {:allow, 1} = TotpRateLimit.hit(key, window, 1)
      assert {:deny, _retry_after_ms} = TotpRateLimit.hit(key, window, 1)

      Process.sleep(window + 25)

      assert {:allow, 1} = TotpRateLimit.hit(key, window, 1)
    end
  end

  describe "POST /users/two-factor using backup code" do
    test "valid backup code is denied when shared rate-limit bucket is exhausted",
         %{conn: conn, user: user} do
      exhausted_conn =
        Enum.reduce(1..@two_factor_limit, conn, fn _, acc ->
          post(acc, Routes.user_totp_path(acc, :create), %{
            "user" => %{
              "code" => "000000",
              "authentication_type" => "totp"
            }
          })
        end)

      backup_code = Enum.random(user.backup_codes)

      denied_conn =
        post(exhausted_conn, Routes.user_totp_path(exhausted_conn, :create), %{
          "user" => %{
            "code" => backup_code.code,
            "authentication_type" => "backup_code"
          }
        })

      assert html_response(denied_conn, 200) =~
               "Invalid two-factor authentication code"

      refute get_session(denied_conn, @totp_session) == nil
    end

    test "validates the backup code correctly", %{conn: conn, user: user} do
      backup_code = Enum.random(user.backup_codes)

      conn =
        post(conn, Routes.user_totp_path(conn, :create), %{
          "user" => %{
            "code" => "wrong code",
            "authentication_type" => "backup_code"
          }
        })

      response = html_response(conn, 200)
      assert response =~ "Invalid two-factor authentication code"
      refute get_session(conn, @totp_session) == nil

      conn =
        post(conn, Routes.user_totp_path(conn, :create), %{
          "user" => %{
            "code" => backup_code.code,
            "authentication_type" => "backup_code"
          }
        })

      assert redirected_to(conn) == "/projects"
      assert get_session(conn, @totp_session) == nil
    end

    test "logs the user in with remember me", %{conn: conn, user: user} do
      backup_code = Enum.random(user.backup_codes)

      conn =
        post(conn, Routes.user_totp_path(conn, :create), %{
          "user" => %{
            "code" => backup_code.code,
            "authentication_type" => "backup_code",
            "remember_me" => "true"
          }
        })

      assert redirected_to(conn) == "/projects"
      assert get_session(conn, @totp_session) == nil
      assert conn.resp_cookies["_lightning_web_user_remember_me"]
    end

    test "logs the user in with return to", %{conn: conn, user: user} do
      backup_code = Enum.random(user.backup_codes)

      conn =
        conn
        |> put_session(:user_return_to, "/return_here")
        |> post(Routes.user_totp_path(conn, :create), %{
          "user" => %{
            "code" => backup_code.code,
            "authentication_type" => "backup_code"
          }
        })

      assert redirected_to(conn) == "/return_here"
      assert get_session(conn, @totp_session) == nil
    end
  end

  defp bucket_for(%{id: id}) do
    "#{@two_factor_bucket}::#{id}"
  end
end
