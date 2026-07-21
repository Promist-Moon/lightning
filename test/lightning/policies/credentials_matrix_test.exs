defmodule Lightning.Policies.CredentialsMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.Policies.Credentials

  @expected_actions [
    :create_keychain_credential,
    :edit_keychain_credential,
    :delete_keychain_credential,
    :view_keychain_credential
  ]

  @create_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow,
    non_member: :deny,
    support_user: :deny
  }

  @manage_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow,
    non_member: :deny,
    support_user: :allow
  }

  setup do
    viewer = insert(:user)
    editor = insert(:user)
    admin = insert(:user)
    owner = insert(:user)
    non_member = insert(:user)
    support_user = insert(:user, support_user: true)

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

    keychain_credential =
      insert(:keychain_credential,
        project: project,
        created_by: owner
      )

    users_by_persona = %{
      viewer: viewer,
      editor: editor,
      admin: admin,
      owner: owner,
      non_member: non_member,
      support_user: support_user
    }

    %{
      project: project,
      project_with_support_access: %{project | allow_support_access: true},
      keychain_credential: keychain_credential,
      users_by_persona: users_by_persona
    }
  end

  test "matrix actions are fully covered" do
    assert_actions_covered!(
      [
        %{action: :create_keychain_credential, matrix: @create_matrix},
        %{action: :edit_keychain_credential, matrix: @manage_matrix},
        %{action: :delete_keychain_credential, matrix: @manage_matrix},
        %{action: :view_keychain_credential, matrix: @manage_matrix}
      ],
      @expected_actions
    )
  end

  test "creation matrix is omission-complete and correct", ctx do
    assert_policy_matrix!(
      Credentials,
      [%{action: :create_keychain_credential, matrix: @create_matrix}],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project}
      end
    )
  end

  test "management matrices are omission-complete and correct", ctx do
    assert_policy_matrix!(
      Credentials,
      [
        %{action: :edit_keychain_credential, matrix: @manage_matrix},
        %{action: :delete_keychain_credential, matrix: @manage_matrix},
        %{action: :view_keychain_credential, matrix: @manage_matrix}
      ],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.keychain_credential}
      end
    )
  end

  test "support access enables support_user creation", ctx do
    matrix = Map.put(@create_matrix, :support_user, :allow)

    assert_policy_matrix!(
      Credentials,
      [%{action: :create_keychain_credential, matrix: matrix}],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project_with_support_access}
      end
    )
  end
end
