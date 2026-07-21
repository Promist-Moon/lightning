defmodule Lightning.Policies.SandboxesMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

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
    owner: :allow,
    non_member: :deny,
    support_user: :deny
  }

  @admin_owner_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow,
    non_member: :deny,
    support_user: :deny
  }

  setup do
    viewer = insert(:user)
    editor = insert(:user)
    admin = insert(:user)
    owner = insert(:user)
    non_member = insert(:user)
    support_user = insert(:user, support_user: true)

    root_project =
      insert(:project,
        project_users: [
          %{user_id: viewer.id, role: :viewer},
          %{user_id: editor.id, role: :editor},
          %{user_id: admin.id, role: :admin},
          %{user_id: owner.id, role: :owner}
        ]
      )

    sandbox = insert(:sandbox, parent: root_project)

    users_by_persona = %{
      viewer: viewer,
      editor: editor,
      admin: admin,
      owner: owner,
      non_member: non_member,
      support_user: support_user
    }

    %{
      root_project: root_project,
      sandbox: sandbox,
      users_by_persona: users_by_persona
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
    assert_policy_matrix!(
      Sandboxes,
      [
        %{action: :provision_sandbox, matrix: @editor_plus_matrix},
        %{action: :merge_sandbox, matrix: @editor_plus_matrix}
      ],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.root_project}
      end
    )
  end

  test "update and delete are omission-complete and correct", ctx do
    assert_policy_matrix!(
      Sandboxes,
      [
        %{action: :update_sandbox, matrix: @admin_owner_matrix},
        %{action: :delete_sandbox, matrix: @admin_owner_matrix}
      ],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.sandbox}
      end
    )
  end
end
