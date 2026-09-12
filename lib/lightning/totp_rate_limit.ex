defmodule Lightning.TotpRateLimit do
  @moduledoc """
  Fixed-window rate limiter for TOTP verification attempts backed by Mnesia.
  """

  use Hammer, backend: Hammer.Mnesia, table: __MODULE__, algorithm: :fix_window
end
