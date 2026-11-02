import os

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.getenv("VULNX_BASE_URL", "http://127.0.0.1:3000")


@pytest.mark.parametrize("width,height", [(390, 844), (768, 1024), (1365, 900)])
def test_dashboard_renders_without_horizontal_overflow(page: Page, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    page.goto(BASE_URL, wait_until="domcontentloaded")

    expect(page.locator("body")).to_be_visible()
    expect(page.locator("#root")).to_be_visible()

    # Allow the React app to finish its initial render before measuring layout.
    page.wait_for_timeout(500)
    dimensions = page.evaluate(
        """() => ({
            viewport: document.documentElement.clientWidth,
            document: document.documentElement.scrollWidth,
            body: document.body.scrollWidth
        })"""
    )
    assert dimensions["document"] <= dimensions["viewport"] + 1, (
        f"Horizontal overflow at {width}x{height}: {dimensions}"
    )
    assert dimensions["body"] <= dimensions["viewport"] + 1, (
        f"Body overflow at {width}x{height}: {dimensions}"
    )


def test_app_has_no_uncaught_page_errors(page: Page) -> None:
    page_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.goto(BASE_URL, wait_until="domcontentloaded")
    page.wait_for_timeout(750)
    assert not page_errors, "Uncaught browser errors: " + " | ".join(page_errors)
