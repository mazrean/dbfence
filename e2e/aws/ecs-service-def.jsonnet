// Never deployed: `ecspresso run` reads the launch type and the network
// configuration of the task from it.
local env = std.native('env');
local must_env = std.native('must_env');

{
  launchType: 'FARGATE',
  platformVersion: 'LATEST',
  networkConfiguration: {
    awsvpcConfiguration: {
      subnets: std.split(must_env('DBFENCE_E2E_ECS_SUBNETS'), ','),
      securityGroups: std.split(must_env('DBFENCE_E2E_ECS_SECURITY_GROUPS'), ','),
      assignPublicIp: env('DBFENCE_E2E_ECS_ASSIGN_PUBLIC_IP', 'DISABLED'),
    },
  },
}
