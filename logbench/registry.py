"""Architecture inventory. Registration does not claim method implementation."""
METHODS = {
    'generic': ['PCA', 'OCSVM', 'IsolationForest', 'LOF', 'Semantic'],
    'log': ['DeepLog', 'LogAnomaly', 'LogBERT', 'LogRobust', 'PLELog', 'LogGPT', 'LogLLM', 'CoLA', 'LogPipe'],
    'provenance': ['MAGIC', 'KAIROS'], 'network': ['KitNET', 'HyperVision'],
    'agent_guard': ['PromptGuard2', 'AlignmentCheck', 'Invariant'],
    'fusion': ['LateFusion', 'CrossAttention']}


def registry():
    result = []
    for family, names in METHODS.items():
        for name in names:
            masks = ['E'] if family == 'provenance' else (['N'] if family == 'network' else (['T'] if family == 'agent_guard' else ['T', 'E', 'N', 'TE', 'TN', 'EN', 'TEN']))
            for mask in ['T', 'E', 'N', 'TE', 'TN', 'EN', 'TEN']:
                result.append({'method': name, 'family': family, 'mask': mask,
                    'architecture_compatible': mask in masks,
                    'runtime_support': 'adapted' if name == 'LateFusion' else 'unsupported',
                    'run_status': 'completed' if name == 'LateFusion' else 'not_run',
                    'reason': 'Lexical T + statistical E/N, linear heads' if name == 'LateFusion' else
                        ('Requires observable reasoning, unavailable' if name == 'AlignmentCheck' else 'Not implemented in this smoke runner'),
                    'source_license_weights': 'Local implementation; sklearn BSD-3-Clause, no external model weights' if name == 'LateFusion' else 'pending; no source or license claim'})
    return result
