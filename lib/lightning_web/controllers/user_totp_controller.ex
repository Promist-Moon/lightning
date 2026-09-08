defmodule LightningWeb.UserTOTPController do
  use LightningWeb, :controller

  alias Lightning.Accounts
  alias LightningWeb.UserAuth

  require Logger

  @two_factor_limit 5
  @two_factor_window :timer.minutes(15)
  @two_factor_bucket "two_factor_verification"

  plug :redirect_if_totp_is_not_pending

  def new(conn, params) do
    render(conn, "new.html",
      error_message: nil,
      remember_me: params["user"]["remember_me"],
      authentication_type: authentication_type(params["authentication_type"])
    )
  end

  def create(conn, %{"user" => params}) do
    current_user = conn.assigns.current_user

    if two_factor_attempt_allowed?(current_user) and
         valid_user_code?(current_user, params) do
      conn
      |> UserAuth.totp_validated()
      |> UserAuth.redirect_with_return_to(params)
    else
      render_invalid_code(conn, params)
    end
  end

  defp redirect_if_totp_is_not_pending(conn, _opts) do
    if UserAuth.totp_pending?(conn) do
      conn
    else
      conn
      |> redirect(to: "/projects")
      |> halt()
    end
  end

  defp authentication_type(type) do
    case type do
      "backup_code" ->
        :backup_code

      _other ->
        :totp
    end
  end

  defp valid_user_code?(user, %{
         "code" => code,
         "authentication_type" => "backup_code"
       }) do
    Accounts.valid_user_backup_code?(user, code)
  end

  defp valid_user_code?(user, %{
         "code" => code,
         "authentication_type" => "totp"
       }) do
    Accounts.valid_user_totp?(user, code)
  end

  defp two_factor_attempt_allowed?(%{id: id}) do
    case Hammer.check_rate(
           "#{@two_factor_bucket}::#{id}",
           @two_factor_window,
           @two_factor_limit
         ) do
      {:allow, _count} ->
        true

      {:deny, _limit} ->
        false

      {:error, reason} ->
        Logger.warning(
          "Two-factor verification rate limiter unavailable, denying verification: " <>
            inspect(reason)
        )

        false
    end
  end

  defp render_invalid_code(conn, params) do
    render(conn, "new.html",
      remember_me: params["remember_me"],
      authentication_type: params["authentication_type"],
      error_message: "Invalid two-factor authentication code"
    )
  end
end
