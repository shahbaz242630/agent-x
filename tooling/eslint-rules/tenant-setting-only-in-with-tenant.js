// ADR-005 §4, SEC-TEN-06: withTenant sets the tenant (the `app.org_id`
// setting) for one transaction only. Set any other way, for example by a
// session-level SET, it would stay on the connection and reach whoever uses
// that pooled connection next. So product code outside withTenant's own file
// may not, in any string or template text:
// - name the setting;
// - call set_config, which could build the name from pieces
//   (`'app.' || 'org_id'`);
// - SET or SET SESSION a two-part setting name, which is how custom settings
//   like app.org_id are written. (UPDATE ... SET col = is not matched: a
//   column there can't take a table prefix.)
// This catches the setting written out; SQL built at run time can still evade
// it, which is why every connection is also checked for a tenant when it is
// opened and each time it is taken from the pool (tenantCheckedPool).
const SETTING = /app\.org_id/i;
const SET_CONFIG = /\bset_config\s*\(/i;
const SET_CUSTOM = /\bset\s+(?:session\s+|local\s+)?"?[a-z_][\w$]*"?\s*\.\s*"?[a-z_]/i;

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Only withTenant names or sets the tenant setting (ADR-005 §4)' },
    schema: [],
    messages: {
      named:
        'ADR-005: only withTenant in @agentx/platform/db sets the tenant, for one transaction. Use withTenant rather than naming app.org_id.',
      setting:
        'ADR-005: product code does not call set_config or SET a custom setting; a setting left on a pooled connection reaches its next user. The tenant is set only by withTenant.',
    },
  },
  create(context) {
    const check = (node, text) => {
      if (SETTING.test(text)) context.report({ node, messageId: 'named' });
      else if (SET_CONFIG.test(text) || SET_CUSTOM.test(text)) context.report({ node, messageId: 'setting' });
    };
    return {
      Literal(node) {
        if (typeof node.value === 'string') check(node, node.value);
      },
      TemplateElement(node) {
        check(node, node.value.cooked ?? node.value.raw);
      },
    };
  },
};
