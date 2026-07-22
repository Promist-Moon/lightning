defmodule Lightning.Policies.CredentialsMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.AuthCoverage.Personas
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
    owner: :allow
  }

  @manage_matrix %{
    viewer: :deny,
    editor: :deny,
    admin: :allow,
    owner: :allow
  }

  setup do
    other_project = insert(:project, allow_support_access: false)

    {users_by_persona_id, owner} =
      Enum.reduce(Personas.all(), {%{}, nil}, fn persona, {users, owner_user} ->
        user = insert(:user)

        users = Map.put(users, persona.id, user)

        case persona.membership_scope do
          :same_project ->
            updated_owner =
              if persona.role == :owner, do: owner_user || user, else: owner_user

            {users, updated_owner}

          :other_project ->
            insert(:project_user,
              user: user,
              project: other_project,
              role: persona.role
            )

            {users, owner_user}

          :none ->
            {users, owner_user}
        end
      end)

    project =
      insert(:project,
        allow_support_access: false,
        project_users:
          Enum.map(
            Personas.roles(),
            &%{user_id: users_by_persona_id[:"#{&1}_same_project"].id, role: &1}
          )
      )

    keychain_credential =
      insert(:keychain_credential,
        project: project,
        created_by: owner
      )

    %{
      project: project,
      keychain_credential: keychain_credential,
      users_by_persona_id: users_by_persona_id
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
    assert_project_scope_policy_matrix!(
      Credentials,
      [%{action: :create_keychain_credential, matrix: @create_matrix}],
      fn persona, _spec ->
        {ctx.users_by_persona_id[persona.id], ctx.project}
      end
    )
  end

  test "management matrices are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      Credentials,
      [
        %{action: :edit_keychain_credential, matrix: @manage_matrix},
        %{action: :delete_keychain_credential, matrix: @manage_matrix},
        %{action: :view_keychain_credential, matrix: @manage_matrix}
      ],
      fn persona, _spec ->
        {ctx.users_by_persona_id[persona.id], ctx.keychain_credential}
      end
    )
  end
end
