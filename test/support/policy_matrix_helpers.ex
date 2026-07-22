defmodule Lightning.PolicyMatrixHelpers do
  @moduledoc false

  import ExUnit.Assertions

  alias Lightning.AuthCoverage.Personas

  @type decision :: :allow | :deny

  def assert_actions_covered!(specs, expected_actions) do
    actual_actions = Enum.map(specs, & &1.action)

    missing = expected_actions -- actual_actions
    extra = actual_actions -- expected_actions

    assert missing == [],
           "Missing action matrix specs: #{inspect(missing)}"

    assert extra == [],
           "Matrix contains unsupported action specs: #{inspect(extra)}"
  end

  def assert_project_role_scope_matrix_complete!(
        action,
        matrix,
        cross_project_overrides \\ %{}
      ) do
    matrix_roles =
      matrix
      |> Map.keys()
      |> Enum.map(&normalize_persona/1)
      |> Enum.uniq()

    expected_roles =
      Personas.roles()
      |> Enum.map(&normalize_persona/1)
      |> Enum.uniq()

    missing = expected_roles -- matrix_roles
    extra = matrix_roles -- expected_roles

    assert missing == [],
           "Action #{inspect(action)} is missing roles: #{inspect(missing)}. " <>
             "expected=#{inspect(expected_roles)} matrix=#{inspect(matrix_roles)}"

    assert extra == [],
           "Action #{inspect(action)} has unknown roles: #{inspect(extra)}. " <>
             "expected=#{inspect(expected_roles)} matrix=#{inspect(matrix_roles)}"

    invalid_matrix_decisions =
      matrix
      |> Enum.reject(fn {_role, decision} -> decision in [:allow, :deny] end)

    assert invalid_matrix_decisions == [],
           "Action #{inspect(action)} has invalid role decisions: " <>
             "#{inspect(invalid_matrix_decisions)}"

    overrides_roles =
      cross_project_overrides
      |> Map.keys()
      |> Enum.map(&normalize_persona/1)
      |> Enum.uniq()

    override_extra = overrides_roles -- expected_roles

    assert override_extra == [],
           "Action #{inspect(action)} has cross-project override keys " <>
             "outside role set: #{inspect(override_extra)}"

    invalid_override_decisions =
      cross_project_overrides
      |> Enum.reject(fn {_role, decision} -> decision in [:allow, :deny] end)

    assert invalid_override_decisions == [],
           "Action #{inspect(action)} has invalid cross-project decisions: " <>
             "#{inspect(invalid_override_decisions)}"
  end

  def assert_project_scope_policy_matrix!(policy_module, specs, subject_builder) do
    personas = Personas.all()

    Enum.each(specs, fn %{action: action, matrix: matrix} = spec ->
      overrides = Map.get(spec, :cross_project_overrides, %{})

      assert_project_role_scope_matrix_complete!(action, matrix, overrides)

      Enum.each(personas, fn persona ->
        {actor, subject} = subject_builder.(persona, spec)

        allowed? = Bodyguard.permit?(policy_module, action, actor, subject)

        expected_allowed? =
          persona
          |> expected_project_scope_decision(spec)
          |> allow?()

        assert allowed? == expected_allowed?,
               "Unexpected decision for #{inspect(policy_module)} #{inspect(action)} " <>
                 "persona #{inspect(persona.id)}: expected #{inspect(expected_allowed?)}, " <>
                 "got #{inspect(allowed?)}"
      end)
    end)
  end

  defp expected_project_scope_decision(
         %Personas{membership_scope: :same_project, role: role},
         %{matrix: matrix}
       ),
       do: Map.fetch!(matrix, role)

  defp expected_project_scope_decision(
         %Personas{membership_scope: :other_project, role: role},
         %{cross_project_overrides: overrides}
       ),
       do: Map.get(overrides, role, :deny)

  defp expected_project_scope_decision(
         %Personas{membership_scope: :other_project, role: _role},
         _spec
       ),
       do: :deny

  # Non-membership stays hard deny for this matrix category by design.
  defp expected_project_scope_decision(
         %Personas{membership_scope: :none},
         _spec
       ),
       do: :deny

  defp allow?(:allow), do: true
  defp allow?(:deny), do: false

  defp normalize_persona(value) when is_atom(value), do: value

  defp normalize_persona(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.trim_leading(":")
    |> String.to_atom()
  end
end
