defmodule Lightning.RateLimit do
  @moduledoc """
  Shared fixed-window rate limiter backed by Mnesia.
  """

  use Hammer, backend: Hammer.Mnesia, table: __MODULE__, algorithm: :fix_window
end
