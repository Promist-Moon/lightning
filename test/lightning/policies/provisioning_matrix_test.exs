defmodule Lightning.Policies.ProvisioningMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.Policies.Provisioning
  alias Lightning.Projects.Project

  @expected_personas [
    :viewer,
    :editor,
    :admin,
    :owner,
    :non_member,
    :support_user,
    :superuser
  ]

  @expected_actions [
    :provision_project,
    :describe_project
  ]

  @provision_existing_project_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow,
    non_member: :deny,
    support_user: :deny,
    superuser: :deny
  }

  @describe_project_matrix %{
    viewer: :allow,
    editor: :allow,
    admin: :allow,
    owner: :allow,
    non_member: :deny,
    support_user: :deny,
    superuser: :deny
  }

  @provision_new_project_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :deny,
    owner: :deny,
    non_member: :deny,
    support_user: :deny,
    superuser: :allow
  }

  setup do
    viewer = insert(:user)
    editor = insert(:user)
    admin = insert(:user)
    owner = insert(:user)
    non_member = insert(:user)
    support_user = insert(:user, support_user: true)
    superuser = insert(:user, role: :superuser)

    project =
      insert(:project,
        allow_support_access: false,
        project_users: [
          %{user_id: viewer.id, role: :viewer},
          %{user_id: editor.id, role: :editor},
          %{user_id: admin.id, role: :admin},
          %{user_id: owner.id, role: :owner}
        ]
      )

    users_by_persona = %{
      viewer: viewer,
      editor: editor,
      admin: admin,
      owner: owner,
      non_member: non_member,
      support_user: support_user,
      superuser: superuser
    }

    %{
      project: project,
      project_with_support_access: %{project | allow_support_access: true},
      users_by_persona: users_by_persona
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
    assert_policy_matrix!(
      Provisioning,
      [
        %{
          action: :provision_project,
          matrix: @provision_existing_project_matrix
        },
        %{action: :describe_project, matrix: @describe_project_matrix}
      ],
      @expected_personas,
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project}
      end
    )
  end

  test "support access allows support_user to describe project", ctx do
    describe_matrix = Map.put(@describe_project_matrix, :support_user, :allow)

    assert_policy_matrix!(
      Provisioning,
      [%{action: :describe_project, matrix: describe_matrix}],
      @expected_personas,
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project_with_support_access}
      end
    )
  end

  test "new project provisioning allows only superuser", ctx do
    assert_policy_matrix!(
      Provisioning,
      [%{action: :provision_project, matrix: @provision_new_project_matrix}],
      @expected_personas,
      fn persona, _spec ->
        {ctx.users_by_persona[persona], %Project{id: nil}}
      end
    )
  end
end
