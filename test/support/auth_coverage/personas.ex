defmodule Lightning.AuthCoverage.Personas do
  @moduledoc """
  Project-scope personas for authorization matrix testing.

  Roles are pulled from the ProjectUser role enum (source of truth), so a
  new role added to the schema automatically becomes a required persona
  everywhere this feeds a matrix test -- nothing here is hand-maintained.

  User-scope personas (instance role, support_user) are intentionally out
  of scope for this module; they're a separate dimension layered on later.
  """

  alias Lightning.Projects.ProjectUser

  @type membership_scope :: :same_project | :other_project | :none

  @type t :: %__MODULE__{
          id: atom(),
          role: atom() | nil,
          membership_scope: membership_scope()
        }

  defstruct [:id, :role, :membership_scope]

  @doc "All project roles are derived from the enum"
  def roles, do: enum_atoms(ProjectUser.RolesEnum.__valid_values__())

  @doc "One persona per role, as a member of the project under test."
  def same_project_members do
    for role <- roles() do
      %__MODULE__{
        id: :"#{role}_same_project",
        role: role,
        membership_scope: :same_project
      }
    end
  end

  @doc """
  One persona per role, held on a DIFFERENT project than the one under
  test. Catches "checks role, not project_id" bugs -- a user who is a
  legitimate owner/admin/editor/viewer elsewhere should still be denied
  here unless an action is explicitly declared cross-project-allowed.
  """
  def cross_project_members do
    for role <- roles() do
      %__MODULE__{
        id: :"#{role}_other_project",
        role: role,
        membership_scope: :other_project
      }
    end
  end

  def non_member do
    %__MODULE__{id: :non_member, role: nil, membership_scope: :none}
  end

  @doc "Default persona set for any project-scoped action matrix."
  def all do
    same_project_members() ++ cross_project_members() ++ [non_member()]
  end

  defp enum_atoms(values) do
    values
    |> Enum.map(&normalize/1)
    |> Enum.uniq()
  end

  defp normalize(v) when is_atom(v), do: v

  defp normalize(v) when is_binary(v),
    do: v |> String.trim_leading(":") |> String.to_atom()
end
