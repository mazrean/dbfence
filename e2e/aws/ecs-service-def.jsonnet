// Never deployed: `ecspresso run` reads the launch type and the network
// configuration of the task from it.
local tfstate = std.native('tfstate');

{
  launchType: 'FARGATE',
  platformVersion: 'LATEST',
  networkConfiguration: {
    awsvpcConfiguration: {
      subnets: tfstate('output.ecs_task_subnet_ids'),
      securityGroups: tfstate('output.ecs_task_security_group_ids'),
      assignPublicIp: tfstate('output.ecs_task_assign_public_ip'),
    },
  },
}
