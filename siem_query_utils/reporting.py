"""
Reporting helpers for PDF and HTML output
"""
import hashlib
import importlib
import pickle
import tempfile
from pathlib import Path
from string import Template
from typing import Union

import esparto
import pandas
import seaborn
import tinycss2
from cloudpathlib import AnyPath
from IPython import display

from .api import OutputFormat, load_dataframes, settings, list_workspaces, load_templates
from .azcli import clean_path, logger

# Global default settings
pandas.set_option("display.max_colwidth", None)
seaborn.set_theme(
    style="darkgrid",
    context="paper",
    font_scale=0.7,
    rc={
        "figure.figsize": (7, 3),
        "figure.constrained_layout.use": True,
        "legend.loc": "upper right",
    },
)

    
class EspartoReport:
    """
    Reporting helpers
    """

    base_css = tinycss2.parse_stylesheet(open(esparto.options.esparto_css, encoding="utf8").read())
    pdf_css = Template(importlib.resources.read_text(f"{__package__}.templates", "esparto-pdf.css"))

    def __init__(
        self,
        agency: str,
        path: Union[Path, AnyPath] = None,
        template: str = None,
        background: str = "markdown/background.png",
        query_cache: str = None,
    ):
        """
        Convenience tooling for loading pandas dataframes using context from a path.
        path is expected to be pathlib type object with a structure like below:
        .
        `--{subfolder} (default is notebooks)
           |--kql
           |  |--*/*.kql
           |--lists
           |  |--SentinelWorkspaces.csv
           |  `--SecOps Groups.csv
           |--markdown
           |  `--**.md
           `--reports
              `--*/*/*.pdf
        """
        if not path:
            path = settings("datalake_path") / "notebooks"
        self.path = path
        self.background = background
        self.pdf_css_file = tempfile.NamedTemporaryFile(delete=False, mode="w+t", suffix=".css")
        self.today = pandas.Timestamp("today")
        # if sample_only = True, build report with only mock data
        # if sample_only = False, build report as usual, only substituting missing data with sample data
        # sections should 'anonymise' sample data prior to rendering
        wsdf = list_workspaces(OutputFormat.DF)
        self.agency = agency
        if agency == "ALL":
            self.agency_name = "Overview"
        else:
            self.agency_info = wsdf[wsdf.alias == agency]
            self.agency_name = self.agency_info["Primary Agency"].max()
        if not template:
            template = (settings("datalake_path") / clean_path("notebooks/wasoc-notebook/report-monthly.md")).read_text()
        self.report_title, self.report_sections = load_templates(mdtemplate=template)
        if not query_cache:
            self.query_cache = self.path / f"query_cache/{self.today.strftime('%Y-%m')}/{agency}_data.zip"
        self.queries = load_dataframes(self.query_cache)
        self.report = esparto.Page(title=self.report_title)

    def init_report(self, table_of_contents=True, **css_params) -> esparto.Page:
        """
        Render the report title and table of contents after applying css

        Args:
            table_of_contents (bool, optional): Whether to render a table of contents. Defaults to True.

        Returns:
            esparto.Page: The report object
        """
        # Return an esparto page for reporting after customising css
        base_css = [
            r for r in self.base_css if not hasattr(r, "at_keyword")
        ]  # strip media/print styles so we can replace

        background = self.path / self.background
        background_file = tempfile.NamedTemporaryFile(delete=False, mode="w+b", suffix="png")
        background_file.write(background.read_bytes())
        background_file.flush()
        css_params["background"] = f"file://{background_file.name}"
        extra_css = tinycss2.parse_stylesheet(
            self.pdf_css.substitute(title=self.report_title, **css_params)
        )
        for rule in base_css + extra_css:
            self.pdf_css_file.write(rule.serialize())
        self.pdf_css_file.flush()
        self.report = esparto.Page(
            title=self.report_title,
            table_of_contents=table_of_contents,
            output_options=esparto.OutputOptions(esparto_css=self.pdf_css_file.name),
        )
        # css not appearing to be utilised correctly, fallback global set
        esparto.options.esparto_css = self.pdf_css_file.name
        return self.report

    def report_pdf(self, preview=True, savehtml=False):
        report_dir = self.path / f"reports/{self.agency}"
        report_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{self.today.strftime('%Y-%m')} {self.report_title} ({self.agency}).pdf"
        pdf_file = report_dir / clean_path(filename)
        data_file = pdf_file.with_suffix(".zip")
        data_file = data_file.with_name(data_file.name.replace("Report", "Report Data"))
        data_file.write_bytes(self.query_cache.read_bytes())
        with tempfile.NamedTemporaryFile(mode="w+b", suffix=".pdf") as pdf_file_tmp:
            html = self.report.save_pdf(pdf_file_tmp, return_html=True)
            pdf_file_tmp.seek(0)
            pdf_file.write_bytes(pdf_file_tmp.read())

        if savehtml:
            pdf_file.with_suffix(".html").write_text(html)

        if preview:
            return display.IFrame(pdf_file, width=1200, height=800)
        else:
            return pdf_file

    def rename_and_sort(self, df, names, rows=40, cols=40):
        # Rename columns based on dict
        df = df.rename(columns=names)
        # Merge common columns
        df = df.groupby(by=df.columns, axis=1).sum()
        # Sort columns by values, top 40
        df = df[df.sum(0).sort_values(ascending=False)[:cols].index]
        # Sort rows by values, top 40
        df = df.loc[df.sum(axis=1).sort_values(ascending=False)[:rows].index]
        return df

    @classmethod
    def label_size(
        cls,
        dataframe: pandas.DataFrame,
        category: str,
        metric: str,
        max_categories=9,
        quantile=0.5,
        max_scale=10,
        agg="sum",
        field="oversized",
    ):
        """
        Annotates a dataframe based on quantile and category sizes, then groups small categories into other
        """
        df = dataframe.copy(deep=True)
        sizes = df.groupby(category)[metric].agg(agg).sort_values(ascending=False)
        maxmetric = sizes.quantile(quantile) * max_scale
        normal, oversized = sizes[sizes <= maxmetric], sizes[sizes > maxmetric]
        df[field] = df[category].isin(oversized.index)
        for others in (normal[max_categories:], oversized[max_categories:]):
            df[category] = df[category].replace(
                {label: f"{others.count()} Others" for label in others.index}
            )
        return df

    @classmethod
    def latest_data(cls, df: pandas.DataFrame, timespan: str, col="TimeGenerated"):
        """
        Return dataframe filtered by timespan
        """
        df = df.copy(deep=True)
        return df[df[col] >= (df[col].max() - pandas.to_timedelta(timespan))].reset_index()

    @classmethod
    def hash256(cls, obj, truncate: int = 16):
        return hashlib.sha256(pickle.dumps(obj)).hexdigest()[:truncate]

    @classmethod
    def hash_columns(cls, dataframe: pandas.DataFrame, columns: list):
        if not isinstance(columns, list):
            columns = [columns]
        for column in columns:
            dataframe[column] = dataframe[column].apply(cls.hash256)

    def show(self, section: str):
        return display.HTML(self.report[section].to_html(notebook_mode=True))
