"""Only a fixed synthetic process payload is registered; no model CLI."""
from .adapters import AdapterRegistry, AdapterError, LocalProcessPolicy, sanitized_environment


class SyntheticProcessAdapter:
    key = 'synthetic_process'
    version = '1.0'

    def __init__(self, launcher, workspaces):
        self.launcher, self.workspaces = launcher, workspaces

    def execute(self, dispatch, context):
        workspace = self.workspaces.create()
        session = None
        launch_unconfirmed = False
        try:
            policy = LocalProcessPolicy(self.launcher.allowlist.executable, workspace.path,
                ('-I', '-S', '-B', str(self.launcher.allowlist.payload)))
            environment = {**sanitized_environment(), **{key:str(workspace.path)
                for key in ('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA')}}
            session = self.launcher.launch(policy, stdin_payload=dispatch.prompt.encode('utf-8'),
                environment=environment, shell=False, workspace=workspace)
            return session.bounded_result(context)
        except AdapterError as failure:
            launch_unconfirmed = failure.code=='PROCESS_TREE_TERMINATION_UNCONFIRMED'
            raise
        finally:
            if session is not None:
                session.terminate_tree_and_wait()
                workspace.termination_confirmed = session.termination_confirmed
            elif not launch_unconfirmed:
                workspace.termination_confirmed = True
            if not launch_unconfirmed:
                workspace.close()


def process_registry(launcher, workspaces):
    registry = AdapterRegistry()
    registry._allowlisted['synthetic_process'] = SyntheticProcessAdapter(launcher, workspaces)
    return registry
