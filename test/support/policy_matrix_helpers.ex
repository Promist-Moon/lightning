defmodule Lightning.PolicyMatrixHelpers do
  @moduledoc false

  import ExUnit.Assertions

  alias Lightning.Accounts.User
  alias Lightning.Projects.ProjectUser

  @type decision :: :allow | :deny

  def project_role_personas do
    enum_to_atoms(ProjectUser.RolesEnum.__valid_values__())
  end

  def instance_role_personas do
    enum_to_atoms(User.RolesEnum.__valid_values__())
  end

  def expected_project_personas(extra \\ [:non_member, :support_user]) do
    project_role_personas() ++ extra
  end

  def assert_actions_covered!(specs, expected_actions) do
    actual_actions = Enum.map(specs, & &1.action)

    missing = expected_actions -- actual_actions
    extra = actual_actions -- expected_actions

    assert missing == [],
           "Missing action matrix specs: #{inspect(missing)}"

    assert extra == [],
           "Matrix contains unsupported action specs: #{inspect(extra)}"
  end

  def assert_matrix_complete!(action, matrix, expected_personas) do
    matrix_personas =
      matrix
      |> Map.keys()
      |> Enum.map(&normalize_persona/1)
      |> Enum.uniq()

    expected_personas =
      expected_personas
      |> Enum.map(&normalize_persona/1)
      |> Enum.uniq()

    missing = expected_personas -- matrix_personas
    extra = matrix_personas -- expected_personas

    assert missing == [],
           "Action #{inspect(action)} is missing personas: #{inspect(missing)}. " <>
             "expected=#{inspect(expected_personas)} matrix=#{inspect(matrix_personas)}"

    assert extra == [],
           "Action #{inspect(action)} has unknown personas: #{inspect(extra)}. " <>
             "expected=#{inspect(expected_personas)} matrix=#{inspect(matrix_personas)}"

    invalid_decisions =
      matrix
      |> Enum.reject(fn {_persona, decision} -> decision in [:allow, :deny] end)

    assert invalid_decisions == [],
           "Action #{inspect(action)} has invalid decisions: #{inspect(invalid_decisions)}"
  end

  def assert_policy_matrix!(
        policy_module,
        specs,
        expected_personas,
        subject_builder
      ) do
    Enum.each(specs, fn %{action: action, matrix: matrix} = spec ->
      assert_matrix_complete!(action, matrix, expected_personas)

      Enum.each(expected_personas, fn persona ->
        {actor, subject} = subject_builder.(persona, spec)

        allowed? = Bodyguard.permit?(policy_module, action, actor, subject)

        expected_allowed? = matrix |> Map.fetch!(persona) |> allow?()

        assert allowed? == expected_allowed?,
               "Unexpected decision for #{inspect(policy_module)} #{inspect(action)} " <>
                 "persona #{inspect(persona)}: expected #{inspect(expected_allowed?)}, " <>
                 "got #{inspect(allowed?)}"
      end)
    end)
  end

  defp allow?(:allow), do: true
  defp allow?(:deny), do: false

  defp enum_to_atoms(values) do
    Enum.map(values, &normalize_persona/1)
  end

  defp normalize_persona(value) when is_atom(value), do: value

  defp normalize_persona(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.trim_leading(":")
    |> String.to_atom()
  end
end
