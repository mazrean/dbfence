// The task runs e2e/run.sh once against the Aurora cluster of one engine.
local env = std.native('env');
local must_env = std.native('must_env');

local engine = must_env('DBFENCE_E2E_ENGINE');
local region = must_env('AWS_REGION');

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
  executionRoleArn: must_env('DBFENCE_E2E_ECS_EXECUTION_ROLE_ARN'),
  taskRoleArn: must_env('DBFENCE_E2E_ECS_TASK_ROLE_ARN'),
  containerDefinitions: [
    {
      name: 'dbfence-e2e',
      image: must_env('DBFENCE_E2E_IMAGE'),
      essential: true,
      environment: [
        { name: 'AWS_REGION', value: region },
        { name: 'DBFENCE_E2E_TARGET', value: 'aws-' + engine },
        { name: 'DBFENCE_E2E_HOST', value: must_env('DBFENCE_E2E_HOST') },
        { name: 'DBFENCE_E2E_PORT', value: env('DBFENCE_E2E_PORT', if engine == 'postgres' then '5432' else '3306') },
        { name: 'DBFENCE_E2E_ADMIN_USER', value: must_env('DBFENCE_E2E_ADMIN_USER') },
        // The ARN of the secret, not the password: dbfence reads it with
        // aws_secretsmanager through the task role.
        { name: 'DBFENCE_E2E_ADMIN_SECRET', value: must_env('DBFENCE_E2E_ADMIN_SECRET') },
      ],
      logConfiguration: {
        // awslogs lets `ecspresso run` stream the output.
        logDriver: 'awslogs',
        options: {
          'awslogs-group': must_env('DBFENCE_E2E_ECS_LOG_GROUP'),
          'awslogs-region': region,
          'awslogs-stream-prefix': 'dbfence-e2e',
        },
      },
    },
  ],
}
