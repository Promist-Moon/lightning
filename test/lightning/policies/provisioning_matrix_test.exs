defmodule Lightning.Policies.ProvisioningMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.AuthCoverage.Personas
  alias Lightning.Policies.Provisioning

  @expected_actions [
    :provision_project,
    :describe_project
  ]

  @provision_existing_project_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow
  }

  @describe_project_matrix %{
    viewer: :allow,
    editor: :allow,
    admin: :allow,
    owner: :allow
  }

  setup do
    other_project = insert(:project, allow_support_access: false)

    {users_by_persona_id, project_users} =
      Enum.reduce(Personas.all(), {%{}, []}, fn persona, {users, members} ->
        user = insert(:user)
        users = Map.put(users, persona.id, user)

        case persona.membership_scope do
          :same_project ->
            member = %{user_id: user.id, role: persona.role}
            {users, [member | members]}

          :other_project ->
            insert(:project_user,
              user: user,
              project: other_project,
              role: persona.role
            )

            {users, members}

          :none ->
            {users, members}
        end
      end)

    project =
      insert(:project,
        allow_support_access: false,
        project_users: Enum.reverse(project_users)
      )

    %{
      project: project,
      users_by_persona_id: users_by_persona_id
    }
  end

  test "matrix actions are fully covered" do
    assert_actions_covered!(
      [
        %{
          action: :provision_project,
          matrix: @provision_existing_project_matrix
        },
        %{action: :describe_project, matrix: @describe_project_matrix}
      ],
      @expected_actions
    )
  end

  test "existing project matrices are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      Provisioning,
      [
        %{
          action: :provision_project,
          matrix: @provision_existing_project_matrix
        },
        %{action: :describe_project, matrix: @describe_project_matrix}
      ],
      fn persona, _spec ->
        {ctx.users_by_persona_id[persona.id], ctx.project}
      end
    )
  end
end
