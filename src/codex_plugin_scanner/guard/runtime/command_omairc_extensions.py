"""Structured rules and metadata for the omairc command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    _after_leading_options,
    _segment_matches_executable,
)

# Flag surface verified against omairc's local CLI (`src/omairccli.cpp` in
# fredimachado/omairc). Dispatch requires the literal subcommand as argv[0];
# `--network` is a per-command option with a following value. `send` treats
# `--help` as help only before the target; after the target it is message
# text. `raise` takes no operands. Read-only inventory (`connections`/`list`,
# `status`, `names`, `read`, `conversations`) is intentionally unmatched so
# those commands stay automatic.
#
# Conservative matching covers:
# - Standard launcher variants: omairc, omairc.exe, omairc.cmd
# - Shell wrappers: exec omairc ..., xargs omairc ...
# - Fail-secure option parsing: unknown options still match send/raise
# - Incomplete `omairc send` without a target still reviews

_OMAIRC_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("omairc",),
    ("exec", "omairc"),
    ("xargs", "omairc"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_NETWORK_OPTIONS_WITH_VALUES = frozenset({"--network"})
_WRAPPER_EXECUTABLES = frozenset({"exec", "xargs"})


def _omairc_matcher(*subcommands: str, options_with_values: frozenset[str] = frozenset()) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                *subcommands,
                options_with_values=options_with_values,
                allow_leading_options=launcher[0] in _WRAPPER_EXECUTABLES,
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _WRAPPER_EXECUTABLES else frozenset()
                ),
                fail_secure_unknown_options=True,
            )
            for launcher in _OMAIRC_LAUNCHERS
        )
    )


_OMAIRC_SEND = _omairc_matcher("send", options_with_values=_NETWORK_OPTIONS_WITH_VALUES)
_OMAIRC_RAISE = _omairc_matcher("raise")


@dataclass(frozen=True, slots=True)
class OmaircSendHelpMatcher:
    """Match `omairc send --help` only when help is requested before a target.

    `omairc send '#channel' --help` sends the text `--help` and must stay a
    reviewable send. `--help` is help only while the CLI is still parsing
    options, including `omairc send --network <id> --help`.
    """

    subcommand: str = "send"
    launchers: tuple[tuple[str, ...], ...] = _OMAIRC_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    network_options: frozenset[str] = _NETWORK_OPTIONS_WITH_VALUES

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in _WRAPPER_EXECUTABLES:
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                prefix = (*launcher[1:], self.subcommand)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                if _send_help_requested(candidate_arguments[len(prefix) :], self.network_options):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched omairc send command help requested before a target.",
                        )
                    )
                break
        return tuple(evidence)


def _send_help_requested(arguments: tuple[str, ...], network_options: frozenset[str]) -> bool:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return False
        if argument in network_options:
            index += 2
            continue
        option_name, separator, _value = argument.partition("=")
        if option_name in network_options and separator == "=":
            index += 1
            continue
        if argument == "--help":
            return True
        if argument.startswith("-"):
            index += 1
            continue
        return False
    return False


OMAIRC_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "omairc message send command": ("network_egress",),
    "omairc window raise command": ("execution",),
}

OMAIRC_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.omairc.send",
        title="omairc message send",
        description=(
            "Identifies `omairc send`, which delivers a PRIVMSG through a running "
            "Omairc window without changing the selected conversation. Incomplete "
            "send invocations and `--help` after the target stay reviewable because "
            "they cannot prove a message will not be delivered. Uncertain parses of "
            "send still review instead of implying safety."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("Omairc message send command",),
        safer_alternatives=(
            "Confirm the network, target, and exact message text before sending.",
            "Use omairc read, names, status, or connections to inspect state first.",
            "Do not retry send when the CLI reports an uncertain result; confirm with read --last.",
        ),
        matcher=_OMAIRC_SEND,
        default_mode="review",
        safe_variants=(
            CommandSafeVariant(
                variant_id="help",
                title="omairc send command help",
                matcher=OmaircSendHelpMatcher(),
            ),
        ),
        example_command="omairc send",
    ),
    CommandSafetyRule(
        rule_id="command.omairc.raise",
        title="omairc window raise",
        description=(
            "Identifies `omairc raise`, which activates the existing Omairc window. "
            "Raise is reviewed because it changes the user's desktop focus."
        ),
        severity="medium",
        risk_classes=("execution",),
        action_classes=("Omairc window raise command",),
        safer_alternatives=("Do not raise the window unless the user asked to bring Omairc to the front.",),
        matcher=_OMAIRC_RAISE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _OMAIRC_RAISE,
                variant_id="help",
                title="omairc raise command help",
                flag="--help",
            ),
        ),
        example_command="omairc raise",
    ),
)

OMAIRC_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.omairc",
        name="omairc command protection",
        description=(
            "Reviews omairc commands that send IRC messages or raise the running "
            "window. Read-only inventory commands stay automatic."
        ),
        action_classes=(
            "Omairc message send command",
            "Omairc window raise command",
        ),
        risk_classes=("network_egress", "execution"),
        safer_alternatives=(
            "Confirm the network, target, and exact message text before sending.",
            "Use omairc read, names, status, or connections to inspect state first.",
        ),
        reference_urls=("https://github.com/fredimachado/omairc",),
        executables=("omairc",),
        ecosystem_ids=("omairc",),
    ),
)
