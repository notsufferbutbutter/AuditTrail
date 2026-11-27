param workspaceName string = 'workspace-audittrailrg3L0F'
@description('Region of the existing workspace.')
param location string = 'germanywestcentral'
param dcrName string = 'audittrail-events-dcr'
param alertRuleName string = 'audittrail-repeated-login-failures'
@description('Principal (object) ID of the Container App runtime managed identity.')
param runtimeIdentityPrincipalId string

var streamName = 'Custom-AuditTrail_CL'
var tableName = 'AuditTrail_CL'
var metricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource auditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    schema: {
      name: tableName
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Server receipt time used for analysis.' }
        { name: 'EventId', type: 'string', description: 'Source event ID used to deduplicate retries.' }
        { name: 'ApplicationId', type: 'string', description: 'Registered application ID.' }
        { name: 'Environment', type: 'string', description: 'Registered environment.' }
        { name: 'ServiceId', type: 'string', description: 'Registered service ID.' }
        { name: 'Action', type: 'string', description: 'Audit event action.' }
        { name: 'Outcome', type: 'string', description: 'Audit event outcome.' }
        { name: 'ActorType', type: 'string', description: 'Actor category.' }
        { name: 'ActorId', type: 'string', description: 'Actor identifier.' }
        { name: 'OccurredAt', type: 'dateTime', description: 'Source-reported event time.' }
        { name: 'ReceivedAt', type: 'dateTime', description: 'Server-recorded receipt time.' }
      ]
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    streamDeclarations: {
      'Custom-AuditTrail_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'EventId', type: 'string' }
          { name: 'ApplicationId', type: 'string' }
          { name: 'Environment', type: 'string' }
          { name: 'ServiceId', type: 'string' }
          { name: 'Action', type: 'string' }
          { name: 'Outcome', type: 'string' }
          { name: 'ActorType', type: 'string' }
          { name: 'ActorId', type: 'string' }
          { name: 'OccurredAt', type: 'datetime' }
          { name: 'ReceivedAt', type: 'datetime' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'auditWorkspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['auditWorkspace']
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [auditTable]
}

resource ingestionRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, runtimeIdentityPrincipalId, metricsPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      metricsPublisherRoleId
    )
    principalId: runtimeIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource failedLoginAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: alertRuleName
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: 'AuditTrail: repeated login failures'
    description: 'Five or more failed login events for one user and service within five minutes.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    scopes: [workspace.id]
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
    criteria: {
      allOf: [
        {
          query: loadTextContent('repeated-login-failures.kql')
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          dimensions: [
            { name: 'ApplicationId', operator: 'Include', values: ['*'] }
            { name: 'Environment', operator: 'Include', values: ['*'] }
            { name: 'ServiceId', operator: 'Include', values: ['*'] }
            { name: 'ActorId', operator: 'Include', values: ['*'] }
          ]
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
  }
  dependsOn: [auditTable, dcr]
}

output ingestionEndpoint string = reference(dcr.id, '2024-03-11').properties.endpoints.logsIngestion
output dcrImmutableId string = reference(dcr.id, '2024-03-11').properties.immutableId
output ingestionStreamName string = streamName
output workspaceResourceId string = workspace.id
