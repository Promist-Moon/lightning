defmodule Lightning.Policies.ProjectUsersMatrixTest do
  use Lightning.DataCase, async: true

  import Lightning.PolicyMatrixHelpers

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
    :edit_project_user_role,
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
      matrix: %{
        viewer: :allow,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :delete_project,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :deny,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :publish_template,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :deny,
        owner: :deny,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :write_webhook_auth_method,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :write_github_connection,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :edit_project,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :edit_data_retention,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :add_project_user,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :edit_project_user_role,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :remove_project_user,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :create_collection,
      matrix: %{
        viewer: :deny,
        editor: :deny,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :create_workflow,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :edit_workflow,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :delete_workflow,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :run_workflow,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :create_project_credential,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :initiate_github_sync,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :create_channel,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :delete_channel,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    },
    %{
      action: :update_channel,
      matrix: %{
        viewer: :deny,
        editor: :allow,
        admin: :allow,
        owner: :allow,
        non_member: :deny,
        support_user: :allow
      }
    }
  ]

  @project_user_action_specs [
    %{
      action: :edit_digest_alerts,
      matrix: %{
        viewer: :allow,
        editor: :deny,
        admin: :deny,
        owner: :deny,
        non_member: :deny,
        support_user: :deny
      }
    },
    %{
      action: :edit_failure_alerts,
      matrix: %{
        viewer: :allow,
        editor: :deny,
        admin: :deny,
        owner: :deny,
        non_member: :deny,
        support_user: :deny
      }
    }
  ]

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

    viewer_project_user =
      Enum.find(project.project_users, &(&1.user_id == viewer.id))

    project_with_support_access = %{project | allow_support_access: true}
    scheduled_project = %{project | scheduled_deletion: DateTime.utc_now()}

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
      project_with_support_access: project_with_support_access,
      scheduled_project: scheduled_project,
      viewer_project_user: viewer_project_user,
      users_by_persona: users_by_persona
    }
  end

  test "matrix actions are fully covered" do
    specs = @project_action_specs ++ @project_user_action_specs

    assert_actions_covered!(specs, @expected_actions)
  end

  test "project-scoped actions are omission-complete and correct", ctx do
    personas = expected_project_personas()

    assert_policy_matrix!(
      ProjectUsers,
      @project_action_specs,
      personas,
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project}
      end
    )
  end

  test "project-user scoped actions are omission-complete and correct", ctx do
    personas = expected_project_personas()

    assert_policy_matrix!(
      ProjectUsers,
      @project_user_action_specs,
      personas,
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.viewer_project_user}
      end
    )
  end

  test "scheduled deletion denies access_project for everyone", ctx do
    matrix = %{
      viewer: :deny,
      editor: :deny,
      admin: :deny,
      owner: :deny,
      non_member: :deny,
      support_user: :deny
    }

    assert_policy_matrix!(
      ProjectUsers,
      [%{action: :access_project, matrix: matrix}],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.scheduled_project}
      end
    )
  end

  test "support access allows support_user for access_project and publish_template",
       ctx do
    access_matrix = %{
      viewer: :allow,
      editor: :allow,
      admin: :allow,
      owner: :allow,
      non_member: :deny,
      support_user: :allow
    }

    publish_matrix = %{
      viewer: :deny,
      editor: :deny,
      admin: :deny,
      owner: :deny,
      non_member: :deny,
      support_user: :allow
    }

    assert_policy_matrix!(
      ProjectUsers,
      [
        %{action: :access_project, matrix: access_matrix},
        %{action: :publish_template, matrix: publish_matrix}
      ],
      expected_project_personas(),
      fn persona, _spec ->
        {ctx.users_by_persona[persona], ctx.project_with_support_access}
      end
    )
  end
end
