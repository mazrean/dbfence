// The task runs e2e/run.sh once against the Aurora cluster of one engine.
local must_env = std.native('must_env');
local tfstate = std.native('tfstate');

local engine = must_env('DBFENCE_E2E_ENGINE');
local region = must_env('AWS_REGION');
local output(name) = tfstate('output.' + name);

{
  family: 'dbfence-e2e-' + engine,
  requiresCompatibilities: ['FARGATE'],
  networkMode: 'awsvpc',
  cpu: '256',
  memory: '512',
  runtimePlatform: {
    cpuArchitecture: 'X86_64',
    operatingSystemFamily: 'LINUX',
  },
  executionRoleArn: output('ecs_execution_role_arn'),
  taskRoleArn: output('ecs_task_role_arn'),
  containerDefinitions: [
    {
      name: 'dbfence-e2e',
      image: must_env('DBFENCE_E2E_IMAGE'),
      essential: true,
      environment: [
        { name: 'AWS_REGION', value: region },
        { name: 'DBFENCE_E2E_TARGET', value: 'aws-' + engine },
        { name: 'DBFENCE_E2E_HOST', value: output(engine + '_endpoint') },
        { name: 'DBFENCE_E2E_ADMIN_USER', value: output(engine + '_master_username') },
        // The ARN of the secret, not the password: dbfence reads it with
        // aws_secretsmanager through the task role.
        { name: 'DBFENCE_E2E_ADMIN_SECRET', value: output(engine + '_master_user_secret_arn') },
      ],
      logConfiguration: {
        // awslogs lets `ecspresso run` stream the output.
        logDriver: 'awslogs',
        options: {
          'awslogs-group': output('ecs_log_group_name'),
          'awslogs-region': region,
          'awslogs-stream-prefix': 'dbfence-e2e',
        },
      },
    },
  ],
}
