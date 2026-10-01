# Sigma Layer

The first version of this lab validates the existing Wazuh rules directly. A later iteration can add Sigma rules as a portable representation of the same detection hypotheses.

The important design rule is to keep the hypothesis and test fixtures stable when the output format changes. A Wazuh rule and a Sigma rule should be tested against the same positive, negative, and edge-case corpus.
