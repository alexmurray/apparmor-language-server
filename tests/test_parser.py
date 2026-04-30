"""
Parser tests for the AppArmor LSP server.
Run with: pytest tests/test_parser.py -v
"""

from __future__ import annotations

from apparmor_language_server.parser import (
    ABINode,
    AllRuleNode,
    AliasNode,
    CapabilityNode,
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    DbusRuleNode,
    FileRuleNode,
    IoUringRuleNode,
    LinkRuleNode,
    MqueueRuleNode,
    NetworkNode,
    PivotRootRuleNode,
    ProfileNode,
    PtraceRuleNode,
    RE_VARIABLE_DEF,
    RemountRuleNode,
    SignalRuleNode,
    UnixRuleNode,
    UsernsRuleNode,
    VariableDefNode,
    parse_document,
)

# ── Sample profile strings ────────────────────────────────────────────────────

SIMPLE_PROFILE = """\
# AppArmor profile for myapp
profile myapp /usr/bin/myapp {
  include <abstractions/base>

  /etc/myapp.conf r,
  /var/log/myapp.log rw,
  file /usr/bin/myapp ix,
  file r /usr/lib/libmyapp.so*,
  owner file rw @{HOME}/.myapp/**,
  deny file r /dev/dri/{,**},
  capability net_bind_service,
  network inet stream,
}
"""

MULTI_PROFILE = """\
@{HOME} = /home/*/ /root/

profile myapp /usr/bin/myapp {
  include <abstractions/base>
  capability chown dac_override,
  /etc/** r,
}

profile myapp-helper /usr/lib/myapp/helper {
  include <abstractions/base>
  /tmp/** rw,
}
"""

MULTILINE_RULES_PROFILE = """\
profile multiline /usr/bin/multiline {
  network
      inet stream,
  dbus (send)
      bus=session
      path=/org/freedesktop/DBus
      interface=org.freedesktop.DBus
      member="{Request,Release}Name"
      peer=(name=org.freedesktop.DBus, label=unconfined),
  capability
      sys_admin
      chown,
}
"""

PROFILE_USING_HOME = """\
include <tunables/home>

profile home-user {
  @{HOME}/ r,
}
"""


# ── ABI and global tunables ───────────────────────────────────────────────────


class TestABIAndIncludes:
    def test_abi_node_parsed(self):
        src = "abi <abi/5.0>,\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert doc.abi is not None
        assert isinstance(doc.abi, ABINode)
        assert doc.abi.path == "abi/5.0"
        assert doc.abi.angle_bracket is True

    def test_abi_no_hash_syntax(self):
        src = "abi <abi/4.0>,\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert doc.abi is not None
        assert doc.abi.path == "abi/4.0"

    def test_include_angle_bracket(self):
        src = "#include <tunables/global>\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert any(inc.path == "tunables/global" for inc in doc.includes)
        tg_inc = next(i for i in doc.includes if i.path == "tunables/global")
        assert tg_inc.angle_bracket is True
        assert tg_inc.conditional is False

    def test_include_conditional(self):
        src = "profile x {\n  include if exists <local/myapp>\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert any(inc.path == "local/myapp" for inc in doc.includes)
        cond_inc = next(i for i in doc.includes if i.path == "local/myapp")
        assert cond_inc.conditional is True

    def test_include_conditional_dotd(self):
        src = "profile x {\n  include if exists <local/myapp.d>\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert any(inc.path == "local/myapp.d" for inc in doc.includes)
        cond_inc = next(i for i in doc.includes if i.path == "local/myapp.d")
        assert cond_inc.conditional is True

    def test_include_non_conditional(self):
        src = "include <abstractions/base>\nprofile x { capability kill, }\n"
        doc, _ = parse_document("file:///test.aa", src)
        abs_inc = next((i for i in doc.includes if i.path == "abstractions/base"), None)
        assert abs_inc is not None
        assert abs_inc.conditional is False

    def test_include_detected(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        assert any(inc.path == "abstractions/base" for inc in doc.includes)


# ── Profile flags ─────────────────────────────────────────────────────────────


class TestProfileFlags:
    def test_single_flag(self):
        src = "profile myapp /usr/bin/myapp flags=(attach_disconnected) {\n  capability kill,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        assert len(doc.profiles) == 1
        assert "attach_disconnected" in doc.profiles[0].flags

    def test_multiple_flags(self):
        src = "profile myapp /usr/bin/myapp flags=(attach_disconnected,mediate_deleted) {\n  capability kill,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        flags = doc.profiles[0].flags
        assert "attach_disconnected" in flags
        assert "mediate_deleted" in flags

    def test_unconfined_flag(self):
        src = (
            "profile myapp /usr/bin/myapp flags=(unconfined) {\n  capability kill,\n}\n"
        )
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        assert "unconfined" in doc.profiles[0].flags

    def test_no_attachment_profile(self):
        src = "profile myapp {\n  capability kill,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        assert doc.profiles[0].name == "myapp"
        assert not doc.profiles[0].attachment


# ── Variable definitions ──────────────────────────────────────────────────────


class TestVariables:
    def test_variable_definition(self):
        doc, _ = parse_document("file:///test.aa", MULTI_PROFILE)
        assert "@{HOME}" in doc.variables

    def test_variable_values(self):
        src = "@{MYVAR} = /opt/myapp/ /usr/local/myapp/\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "@{MYVAR}" in doc.variables
        var = doc.variables["@{MYVAR}"]
        assert "/opt/myapp/" in var.values
        assert "/usr/local/myapp/" in var.values

    def test_variable_augmented(self):
        src = "@{HOME} = /home/*/\n@{HOME} += /root/\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "@{HOME}" in doc.variables
        aug_vars = [
            v for v in doc.children if isinstance(v, VariableDefNode) and v.augmented
        ]
        assert len(aug_vars) >= 1

    def test_exec_path_synthesised(self):
        src = "profile myapp /usr/bin/myapp {\n  capability kill,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "@{exec_path}" in doc.variables
        assert "/usr/bin/myapp" in doc.variables["@{exec_path}"].values

    def test_all_variables_contains_doc_uri(self):
        src = "@{HOME} = /home/*/\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "file:///test.aa" in doc.all_variables

    def test_profile_using_home_variable(self):
        doc, errors = parse_document("file:///test.aa", PROFILE_USING_HOME)
        assert any(inc.path == "tunables/home" for inc in doc.includes)
        found_home_var = False
        for inc in doc.includes:
            if inc.path == "tunables/home":
                for inc_doc in inc.documents:
                    for name in inc_doc.variables:
                        if name == "@{HOME}":
                            found_home_var = True
                            break
        assert found_home_var, (
            "Expected @{HOME} variable to be defined from tunables/home"
        )
        assert len(errors) == 0

    def test_all_variables_after_home_include(self):
        doc, errors = parse_document("file:///test.aa", PROFILE_USING_HOME)
        assert len(errors) == 0
        all_var_names: set[str] = set()
        for vars_dict in doc.all_variables.values():
            all_var_names.update(vars_dict.keys())
        assert "@{HOME}" in all_var_names


# ── Alias rules ───────────────────────────────────────────────────────────────


class TestAliasRules:
    def test_alias_node_parsed(self):
        src = "alias /usr/ -> /mnt/usr/,\nprofile x { }\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        alias_nodes = [c for c in doc.children if isinstance(c, AliasNode)]
        assert len(alias_nodes) == 1
        assert alias_nodes[0].original == "/usr/"
        assert "/mnt/usr/" in alias_nodes[0].replacement


# ── File rules ────────────────────────────────────────────────────────────────


class TestFileRules:
    def test_path_perms_suffix_form(self):
        src = "profile x {\n  /etc/passwd r,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        assert any(f.path == "/etc/passwd" and "r" in f.perms for f in files)

    def test_file_keyword_perms_prefix_form(self):
        src = "profile x {\n  file /usr/bin/app ix,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        assert any(f.path == "/usr/bin/app" and "ix" in f.perms for f in files)

    def test_file_keyword_perms_prefix_form2(self):
        src = "profile x {\n  file r /usr/lib/libfoo.so*,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        assert any(f.path == "/usr/lib/libfoo.so*" and "r" in f.perms for f in files)

    def test_owner_qualifier(self):
        src = "profile x {\n  owner file rw @{HOME}/**,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        home_rule = next((f for f in files if "@{HOME}/**" in f.path), None)
        assert home_rule is not None
        assert "owner" in home_rule.qualifiers
        assert "rw" in home_rule.perms

    def test_deny_qualifier(self):
        src = "profile x {\n  deny file r /dev/dri/{,**},\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        deny_rule = next((f for f in files if "/dev/dri/{,**}" in f.path), None)
        assert deny_rule is not None
        assert "deny" in deny_rule.qualifiers
        assert "r" in deny_rule.perms

    def test_audit_qualifier(self):
        src = "profile x {\n  audit /tmp/** rw,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        audit_rule = next((f for f in files if "/tmp/**" in f.path), None)
        assert audit_rule is not None
        assert "audit" in audit_rule.qualifiers

    def test_allow_file_qualifier(self):
        src = "profile x {\n  allow file rwlkm /{**,},\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        assert len(files) >= 1

    def test_exec_with_link_target(self):
        src = "profile x {\n  /usr/bin/app Cx -> child_profile,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        exec_rule = next((f for f in files if f.path == "/usr/bin/app"), None)
        assert exec_rule is not None
        assert "Cx" in exec_rule.perms
        assert exec_rule.link_target == "child_profile"

    def test_tshark_style_exec_cx(self):
        src = "profile tshark /usr/bin/tshark {\n  file Cx /usr/bin/dumpcap -> dumpcap,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        exec_rule = next((f for f in files if "/usr/bin/dumpcap" in f.path), None)
        assert exec_rule is not None
        assert exec_rule.link_target == "dumpcap"

    def test_pix_exec_with_stacking(self):
        src = "profile x {\n  allow pix /** -> &bwrap//&unpriv_bwrap,\n}\n"
        doc, _ = parse_document("file:///test.aa", src)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        exec_rule = next((f for f in files if f.path == "/**"), None)
        assert exec_rule is not None
        assert "allow" in exec_rule.qualifiers

    def test_simple_profile_file_rules(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        files = [c for c in profile.children if isinstance(c, FileRuleNode)]
        paths = {f.path for f in files}
        assert "/etc/myapp.conf" in paths
        assert "/usr/bin/myapp" in paths
        assert "/usr/lib/libmyapp.so*" in paths
        assert "@{HOME}/.myapp/**" in paths

    def test_home_rule_qualifiers_and_perms(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        home_rule = next(f for f in files if f.path == "@{HOME}/.myapp/**")
        assert "owner" in home_rule.qualifiers
        assert "rw" in home_rule.perms

    def test_deny_rule_qualifiers_and_perms(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        files = [c for c in doc.profiles[0].children if isinstance(c, FileRuleNode)]
        deny_rule = next(f for f in files if f.path == "/dev/dri/{,**}")
        assert "deny" in deny_rule.qualifiers
        assert "r" in deny_rule.perms


# ── Capability rules ──────────────────────────────────────────────────────────


class TestCapabilityRules:
    def test_single_capability(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        caps = [c for c in profile.children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "net_bind_service" in caps[0].capabilities

    def test_multiple_caps_one_line(self):
        src = "profile x {\n  capability chown dac_override,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        caps = [c for c in doc.profiles[0].children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "chown" in caps[0].capabilities
        assert "dac_override" in caps[0].capabilities

    def test_deny_qualifier_on_capability(self):
        src = "profile x {\n  deny capability block_suspend,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        caps = [c for c in doc.profiles[0].children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "deny" in caps[0].qualifiers
        assert "block_suspend" in caps[0].capabilities

    def test_audit_deny_capability(self):
        src = "profile x {\n  audit deny capability mac_admin,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        caps = [c for c in doc.profiles[0].children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "mac_admin" in caps[0].capabilities

    def test_bare_capability_allow_all(self):
        src = "profile x {\n  allow capability,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        caps = [c for c in doc.profiles[0].children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "allow" in caps[0].qualifiers

    def test_multiline_capability_rule(self):
        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        profile = doc.profiles[0]
        caps = [c for c in profile.children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "sys_admin" in caps[0].capabilities
        assert "chown" in caps[0].capabilities


# ── Network rules ─────────────────────────────────────────────────────────────


class TestNetworkRules:
    def test_single_network_family(self):
        src = "profile x {\n  network bluetooth,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        nets = [c for c in doc.profiles[0].children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "bluetooth" in nets[0].rest

    def test_network_family_and_type(self):
        src = "profile x {\n  network x25 seqpacket,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        nets = [c for c in doc.profiles[0].children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "x25" in nets[0].rest
        assert "seqpacket" in nets[0].rest

    def test_allow_bare_network(self):
        src = "profile x {\n  allow network,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        nets = [c for c in doc.profiles[0].children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "allow" in nets[0].qualifiers

    def test_simple_profile_network_rule(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        nets = [c for c in profile.children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "inet" in nets[0].rest

    def test_multiline_network_rule(self):
        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        profile = doc.profiles[0]
        nets = [c for c in profile.children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "inet" in nets[0].rest
        assert "stream" in nets[0].rest

    def test_multiline_network_rule_range(self):
        doc, _ = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        profile = doc.profiles[0]
        net = next(c for c in profile.children if isinstance(c, NetworkNode))
        assert net.range.start.line < net.range.end.line


# ── Generic rules (signal/ptrace/dbus/unix/etc.) ──────────────────────────────


class TestGenericRules:
    def test_signal_basic(self):
        src = "profile x {\n  signal (send) set=(hup term) peer=/usr/sbin/daemon,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert signals[0].permissions == ["send"]
        assert "hup" in signals[0].signal_set
        assert "term" in signals[0].signal_set
        assert signals[0].peer == "/usr/sbin/daemon"

    def test_signal_send_peer(self):
        src = (
            "profile tshark /usr/bin/tshark {\n  signal send peer=tshark//dumpcap,\n}\n"
        )
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert signals[0].permissions == ["send"]
        assert signals[0].peer == "tshark//dumpcap"

    def test_signal_receive_peer(self):
        src = "profile x {\n  signal receive peer=tshark,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert signals[0].permissions == ["receive"]
        assert signals[0].peer == "tshark"

    def test_deny_signal_has_deny_qualifier(self):
        src = "profile x {\n  deny signal (send) set=(term) peer=unconfined,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert "deny" in signals[0].qualifiers
        assert signals[0].permissions == ["send"]
        assert signals[0].signal_set == ["term"]
        assert signals[0].peer == "unconfined"

    def test_signal_bare_no_perms(self):
        src = "profile x {\n  allow signal,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert "allow" in signals[0].qualifiers
        assert signals[0].permissions == []
        assert signals[0].peer is None

    def test_signal_peer_only(self):
        src = "profile x {\n  signal peer=/usr/sbin/cupsd//third_party,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        signals = [c for c in doc.profiles[0].children if isinstance(c, SignalRuleNode)]
        assert len(signals) == 1
        assert signals[0].permissions == []
        assert signals[0].peer == "/usr/sbin/cupsd//third_party"

    def test_ptrace_with_peer(self):
        src = "profile x {\n  ptrace (read) peer=@{profile_name},\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        ptraces = [c for c in doc.profiles[0].children if isinstance(c, PtraceRuleNode)]
        assert len(ptraces) == 1
        assert "ptrace" in ptraces[0].raw

    def test_dbus_send_receive(self):
        src = "profile x {\n  dbus (send receive) bus=session path=/org/example,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        dbus_rules = [
            c for c in doc.profiles[0].children if isinstance(c, DbusRuleNode)
        ]
        assert len(dbus_rules) == 1
        assert "bus=session" in dbus_rules[0].content

    def test_dbus_eavesdrop(self):
        src = "profile tshark_dumpcap /usr/bin/dumpcap {\n  dbus (eavesdrop receive) bus=system,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        dbus_rules = [
            c for c in doc.profiles[0].children if isinstance(c, DbusRuleNode)
        ]
        assert len(dbus_rules) == 1
        assert "eavesdrop" in dbus_rules[0].content

    def test_unix_connect(self):
        src = "profile x {\n  unix (connect) type=stream,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        unix_rules = [
            c for c in doc.profiles[0].children if isinstance(c, UnixRuleNode)
        ]
        assert len(unix_rules) == 1

    def test_unix_peer_label(self):
        src = "profile x {\n  unix peer=(label=/usr/lib/cups/backend/cups-pdf),\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        unix_rules = [
            c for c in doc.profiles[0].children if isinstance(c, UnixRuleNode)
        ]
        assert len(unix_rules) == 1
        assert "label=/usr/lib/cups/backend/cups-pdf" in unix_rules[0].content

    def test_bare_pivot_root(self):
        src = "profile slirp4netns /usr/bin/slirp4netns {\n  pivot_root,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        pivot_roots = [
            c for c in doc.profiles[0].children if isinstance(c, PivotRootRuleNode)
        ]
        assert len(pivot_roots) == 1

    def test_bare_userns(self):
        src = "profile x {\n  userns,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        userns_rules = [
            c for c in doc.profiles[0].children if isinstance(c, UsernsRuleNode)
        ]
        assert len(userns_rules) == 1

    def test_io_uring_sqpoll(self):
        src = "profile x {\n  io_uring (sqpoll),\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        io_rules = [
            c for c in doc.profiles[0].children if isinstance(c, IoUringRuleNode)
        ]
        assert len(io_rules) == 1
        assert "sqpoll" in io_rules[0].content

    def test_mqueue(self):
        src = "profile x {\n  mqueue (read write) type=posix /myqueue,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        mq_rules = [
            c for c in doc.profiles[0].children if isinstance(c, MqueueRuleNode)
        ]
        assert len(mq_rules) == 1

    def test_change_profile(self):
        src = "profile x {\n  change_profile -> /usr/bin/other,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        cp_rules = [
            c for c in doc.profiles[0].children if isinstance(c, ChangeProfileRuleNode)
        ]
        assert len(cp_rules) == 1

    def test_change_hat(self):
        src = "profile x {\n  change_hat DEFAULT,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        ch_rules = [
            c for c in doc.profiles[0].children if isinstance(c, ChangeHatRuleNode)
        ]
        assert len(ch_rules) == 1

    def test_multiline_dbus_rule(self):
        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        profile = doc.profiles[0]
        dbus_rules = [c for c in profile.children if isinstance(c, DbusRuleNode)]
        assert len(dbus_rules) == 1
        assert "bus=session" in dbus_rules[0].content
        assert (
            "peer=(name=org.freedesktop.DBus, label=unconfined)"
            in dbus_rules[0].content
        )

    def test_multiline_dbus_rule_range(self):
        doc, _ = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        profile = doc.profiles[0]
        dbus_rules = [c for c in profile.children if isinstance(c, DbusRuleNode)]
        assert dbus_rules[0].range.start.line < dbus_rules[0].range.end.line


# ── Profile structure ─────────────────────────────────────────────────────────


class TestProfileStructure:
    def test_simple_profile_parses(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        assert len(doc.profiles) == 1
        assert doc.profiles[0].name == "myapp"
        assert len(errors) == 0

    def test_multiple_profiles(self):
        doc, _ = parse_document("file:///test.aa", MULTI_PROFILE)
        assert len(doc.profiles) == 2
        names = {p.name for p in doc.profiles}
        assert "myapp" in names
        assert "myapp-helper" in names

    def test_unclosed_profile_creates_error(self):
        _, errors = parse_document(
            "file:///test.aa", "profile bad {\n  capability kill,\n"
        )
        assert len(errors) >= 1

    def test_nested_profile(self):
        src = """\
profile outer /usr/bin/outer {
  capability kill,
  profile inner {
    capability net_admin,
  }
}
"""
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        outer = doc.profiles[0]
        assert outer.name == "outer"
        inner_profiles = [c for c in outer.children if isinstance(c, ProfileNode)]
        assert len(inner_profiles) == 1
        assert inner_profiles[0].name == "inner"

    def test_hat_sub_profile(self):
        src = """\
profile webapp /usr/sbin/apache2 {
  capability kill,
  hat DEFAULT {
    network inet stream,
  }
}
"""
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        outer = doc.profiles[0]
        hats = [c for c in outer.children if isinstance(c, ProfileNode) and c.is_hat]
        assert len(hats) == 1
        assert hats[0].name == "DEFAULT"
        assert hats[0].is_hat is True


# ── Variable assignment operators ─────────────────────────────────────────────


class TestVariableAssignmentOperators:
    def test_re_variable_def_matches_equals(self):
        assert RE_VARIABLE_DEF.match("@{HOME} = /home/*/")

    def test_re_variable_def_matches_plus_equals(self):
        assert RE_VARIABLE_DEF.match("@{HOME} += /root/")

    def test_re_variable_def_matches_question_equals(self):
        assert RE_VARIABLE_DEF.match("@{HOME} ?= /home/*/")

    def test_re_variable_def_matches_colon_equals(self):
        assert RE_VARIABLE_DEF.match("@{HOME} := /home/*/")

    def test_question_equals_parses(self):
        src = "@{MYVAR} ?= /opt/myapp/\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "@{MYVAR}" in doc.variables

    def test_colon_equals_parses(self):
        src = "@{MYVAR} := /opt/myapp/\nprofile x { }\n"
        doc, _ = parse_document("file:///test.aa", src)
        assert "@{MYVAR}" in doc.variables


# ── New rule types ────────────────────────────────────────────────────────────


class TestNewRuleTypes:
    def test_link_rule_parsed(self):
        src = "profile x {\n  link /foo -> /bar,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        links = [c for c in doc.profiles[0].children if isinstance(c, LinkRuleNode)]
        assert len(links) == 1
        assert links[0].link == "/foo"
        assert links[0].target == "/bar"
        assert links[0].subset is False

    def test_link_subset_rule_parsed(self):
        src = "profile x {\n  link subset /link -> /**,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        links = [c for c in doc.profiles[0].children if isinstance(c, LinkRuleNode)]
        assert len(links) == 1
        assert links[0].subset is True
        assert links[0].link == "/link"
        assert links[0].target == "/**"

    def test_all_rule_parsed(self):
        src = "profile x {\n  all,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        all_rules = [c for c in doc.profiles[0].children if isinstance(c, AllRuleNode)]
        assert len(all_rules) == 1

    def test_remount_rule_parsed(self):
        src = "profile x {\n  remount /mnt,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        assert len(errors) == 0
        remount_rules = [c for c in doc.profiles[0].children if isinstance(c, RemountRuleNode)]
        assert len(remount_rules) == 1
