from siem_query_utils.api import OutputFormat, azcli, list_workspaces
from siem_query_utils.reporting import KQL
import pandas

class TestClass:
    def test_listworkspaces(self):
        assert isinstance(list_workspaces(OutputFormat.df), pandas.DataFrame)

    def test_kql(self):
        kp = KQL()
        assert isinstance(kp.sentinelworkspaces, list)
    
    def test_azcli(self):
        assert "azure-cli" in azcli(["version"])
