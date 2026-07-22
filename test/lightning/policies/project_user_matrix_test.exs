defmodule Lightning.Policies.ProjectUsersMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

  alias Lightning.AuthCoverage.Personas
  alias Lightning.Policies.Permissions
  alias Lightning.Policies.ProjectUsers

  @expected_actions [
    :access_project,
    :delete_project,
    :publish_template,
    :write_webhook_auth_method,
    :write_github_connection,
    :edit_project,
    :edit_data_retention,
    :add_project_user,
    :remove_project_user,
    :create_collection,
    :create_workflow,
    :edit_workflow,
    :delete_workflow,
    :run_workflow,
    :create_project_credential,
    :initiate_github_sync,
    :create_channel,
    :delete_channel,
    :update_channel,
    :edit_digest_alerts,
    :edit_failure_alerts
  ]

  @project_action_specs [
    %{
      action: :access_project,
      matrix: %{viewer: :allow, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :delete_project,
      matrix: %{viewer: :deny, editor: :deny, admin: :deny, owner: :allow}
    },
    %{
      action: :publish_template,
      matrix: %{viewer: :deny, editor: :deny, admin: :deny, owner: :deny}
    },
    %{
      action: :write_webhook_auth_method,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :write_github_connection,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :edit_project,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :edit_data_retention,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :add_project_user,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :remove_project_user,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :create_collection,
      matrix: %{viewer: :deny, editor: :deny, admin: :allow, owner: :allow}
    },
    %{
      action: :create_workflow,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :edit_workflow,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :delete_workflow,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :run_workflow,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :create_project_credential,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :initiate_github_sync,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :create_channel,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :delete_channel,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    },
    %{
      action: :update_channel,
      matrix: %{viewer: :deny, editor: :allow, admin: :allow, owner: :allow}
    }
  ]

  @project_user_action_specs [
    %{
      action: :edit_digest_alerts,
      matrix: %{viewer: :allow, editor: :deny, admin: :deny, owner: :deny}
    },
    %{
      action: :edit_failure_alerts,
      matrix: %{viewer: :allow, editor: :deny, admin: :deny, owner: :deny}
    }
  ]

  @support_equivalent_actions [
    :create_workflow,
    :edit_workflow,
    :delete_workflow,
    :run_workflow,
    :create_project_credential,
    :initiate_github_sync
  ]

  setup do
    project = insert(:project, allow_support_access: false)
    other_project = insert(:project, allow_support_access: false)

    {project_action_actors_by_persona_id, viewer_project_user} =
      Enum.reduce(Personas.all(), {%{}, nil}, fn persona, {actors, viewer_pu} ->
        case persona.membership_scope do
          :same_project ->
            user = insert(:user)

            project_user =
              insert(:project_user,
                user: user,
                project: project,
                role: persona.role
              )

            viewer_project_user =
              if persona.role == :viewer,
                do: viewer_pu || project_user,
                else: viewer_pu

            {Map.put(actors, persona.id, user), viewer_project_user}

          :other_project ->
            user = insert(:user)

            insert(:project_user,
              user: user,
              project: other_project,
              role: persona.role
            )

            {Map.put(actors, persona.id, user), viewer_pu}

          :none ->
            user = insert(:user)
            {Map.put(actors, persona.id, user), viewer_pu}
        end
      end)

    %{
      project: project,
      project_with_support_access: %{project | allow_support_access: true},
      scheduled_project: %{project | scheduled_deletion: DateTime.utc_now()},
      project_action_actors_by_persona_id: project_action_actors_by_persona_id,
      viewer_project_user: viewer_project_user
    }
  end

  test "matrix actions are fully covered" do
    specs = @project_action_specs ++ @project_user_action_specs

    assert_actions_covered!(specs, @expected_actions)
  end

  test "project-scoped actions are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      ProjectUsers,
      @project_action_specs,
      fn persona, _spec ->
        {ctx.project_action_actors_by_persona_id[persona.id], ctx.project}
      end
    )
  end

  test "project-user scoped actions are omission-complete and correct", ctx do
    assert_project_scope_policy_matrix!(
      ProjectUsers,
      @project_user_action_specs,
      fn persona, _spec ->
        {ctx.project_action_actors_by_persona_id[persona.id],
         ctx.viewer_project_user}
      end
    )
  end

  test "scheduled deletion denies access_project for every project-scope persona",
       ctx do
    assert_project_scope_policy_matrix!(
      ProjectUsers,
      [
        %{
          action: :access_project,
          matrix: %{viewer: :deny, editor: :deny, admin: :deny, owner: :deny}
        }
      ],
      fn persona, _spec ->
        {ctx.project_action_actors_by_persona_id[persona.id],
         ctx.scheduled_project}
      end
    )
  end

  test "support user behavior remains explicit outside project-scope personas",
       ctx do
    support_user = insert(:user, support_user: true)

    refute ProjectUsers
           |> Permissions.can?(:access_project, support_user, ctx.project)

    assert ProjectUsers
           |> Permissions.can?(
             :access_project,
             support_user,
             ctx.project_with_support_access
           )

    Enum.each(@support_equivalent_actions, fn action ->
      assert ProjectUsers
             |> Permissions.can?(action, support_user, nil)
    end)

    assert ProjectUsers
           |> Permissions.can?(
             :publish_template,
             support_user,
             ctx.project_with_support_access
           )
  end
end
