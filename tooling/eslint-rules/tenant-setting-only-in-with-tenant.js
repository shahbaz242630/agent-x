// ADR-005 §4, SEC-TEN-06: withTenant sets the tenant (the `app.org_id`
// setting) for one transaction only. Set any other way, for example by a
// session-level SET, it would stay on the connection and reach whoever uses
// that pooled connection next. So product code never names the setting
// outside withTenant's own file: any string or template text that mentions it
// is refused. This catches the setting written out; it can't catch a name
// assembled at run time, which is why a new connection is also checked for a
// preset tenant (refuseTenantPreset).
const SETTING = /app\.org_id/i;

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Only withTenant names the tenant setting (ADR-005 §4)' },
    schema: [],
    messages: {
      named:
        'ADR-005: only withTenant in @agentx/platform/db sets the tenant, for one transaction. Use withTenant rather than naming app.org_id.',
    },
  },
  create(context) {
    return {
      Literal(node) {
        if (typeof node.value === 'string' && SETTING.test(node.value)) context.report({ node, messageId: 'named' });
      },
      TemplateElement(node) {
        if (SETTING.test(node.value.cooked ?? node.value.raw)) context.report({ node, messageId: 'named' });
      },
    };
  },
};
