defmodule Lightning.Policies.SandboxesMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.AuthCoverage.Personas
  alias Lightning.Policies.Sandboxes

  @expected_actions [
    :provision_sandbox,
    :merge_sandbox,
    :update_sandbox,
    :delete_sandbox
  ]

  @editor_plus_matrix %{
    viewer: :deny,
    editor: :allow,
    admin: :allow,
    owner: :allow
  }

  @admin_owner_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow
  }

  setup do
    other_project = insert(:project)

    {users_by_persona_id, root_project_users} =
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

    root_project =
      insert(:project,
        project_users: Enum.reverse(root_project_users)
      )

    sandbox = insert(:sandbox, parent: root_project)

    %{
      root_project: root_project,
      sandbox: sandbox,
      users_by_persona_id: users_by_persona_id
    }
  end

  test "matrix actions are fully covered" do
    assert_actions_covered!(
      [
        %{action: :provision_sandbox, matrix: @editor_plus_matrix},
        %{action: :merge_sandbox, matrix: @editor_plus_matrix},
        %{action: :update_sandbox, matrix: @admin_owner_matrix},
        %{action: :delete_sandbox, matrix: @admin_owner_matrix}
      ],
      @expected_actions
    )
  end

  test "provision and merge are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      Sandboxes,
      [
        %{action: :provision_sandbox, matrix: @editor_plus_matrix},
        %{action: :merge_sandbox, matrix: @editor_plus_matrix}
      ],
      fn persona, _spec ->
        {ctx.users_by_persona_id[persona.id], ctx.root_project}
      end
    )
  end

  test "update and delete are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      Sandboxes,
      [
        %{action: :update_sandbox, matrix: @admin_owner_matrix},
        %{action: :delete_sandbox, matrix: @admin_owner_matrix}
      ],
      fn persona, _spec ->
        {ctx.users_by_persona_id[persona.id], ctx.sandbox}
      end
    )
  end
end
