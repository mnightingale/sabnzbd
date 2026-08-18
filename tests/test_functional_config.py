#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
tests.test_functional_config - Basic testing if Config pages work
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from pytest_httpserver import HTTPServer


import os
from tests.testhelper import (
    SAB_DATA_DIR,
    SAB_HOST,
    SAB_PORT,
    SAB_NEWSSERVER_HOST,
    SAB_NEWSSERVER_PORT,
    SABnzbdBaseTest,
    create_and_read_nzb_fp,
    get_api_result,
    wait_for,
)


class TestBasicPages(SABnzbdBaseTest):
    def test_base_pages(self):
        # Quick-check of all Config pages
        test_urls = ["config", "config/server", "config/categories", "config/scheduling", "config/rss"]

        for test_url in test_urls:
            self.open_page("http://%s:%s/%s" % (SAB_HOST, SAB_PORT, test_url))

    def test_base_submit_pages(self):
        test_urls_with_submit = [
            "config/general",
            "config/folders",
            "config/switches",
            "config/notify",
            "config/special",
        ]

        for test_url in test_urls_with_submit:
            self.open_page("http://%s:%s/%s" % (SAB_HOST, SAB_PORT, test_url))

            # Can only click the visible buttons
            submit_btns = self.selenium_wrapper(self.driver.find_elements, By.CLASS_NAME, "saveButton")
            for submit_btn in submit_btns:
                if submit_btn.is_displayed():
                    break
            else:
                raise NoSuchElementException

            # Click the right button
            self.answer_confirm(accept=False)
            self.click_element(submit_btn)

            # Saving here may or may not raise a restart-request (depends on whether
            # an option actually changed against the test ini), so dismiss it only
            # if it appears. Declining = no restart, so the process keeps serving.
            self.wait_for_save()

            # For Specials page we get redirected after save, so check for no crash
            if "special" in test_url:
                self.no_page_crash()
            else:
                # For others if all is fine, button will be back to normal in 1 second
                wait_for(
                    lambda: submit_btn.text == "Save Changes",
                    timeout=1.5,
                    err_msg=f"submit_btn.text was '{submit_btn.text}' but expected 'Save Changes'",
                )


class TestConfigLogin(SABnzbdBaseTest):
    def test_login(self):
        # Test if base page works
        self.open_page("http://%s:%s/config/general" % (SAB_HOST, SAB_PORT))

        # Set the username and password
        username_imp = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[data-hide='username']")
        username_imp.clear()
        username_imp.send_keys("test_username")
        pass_inp = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[data-hide='password']")
        pass_inp.clear()
        pass_inp.send_keys("test_password")

        # Submit and decline the restart-request (so no restart happens)
        self.answer_confirm(accept=False)
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.CLASS_NAME, "saveButton"))
        self.dismiss_restart_prompt()

        # Open any page and check if we get redirected
        self.open_page("http://%s:%s/config/general" % (SAB_HOST, SAB_PORT))
        assert "/login" in self.driver.current_url

        # Fill nonsense and submit
        username_login = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[name='username']")
        username_login.clear()
        username_login.send_keys("nonsense")
        pass_login = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[name='password']")
        pass_login.clear()
        pass_login.send_keys("nonsense")
        self.click_and_wait_for_page(self.driver.find_element(By.TAG_NAME, "button"))

        # Check if we were denied
        assert (
            "Authentication failed"
            in self.selenium_wrapper(self.driver.find_element, By.CLASS_NAME, "alert-danger").text
        )

        # Fill right stuff
        username_login = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[name='username']")
        username_login.clear()
        username_login.send_keys("test_username")
        pass_login = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[name='password']")
        pass_login.clear()
        pass_login.send_keys("test_password")
        self.click_and_wait_for_page(self.driver.find_element(By.TAG_NAME, "button"))

        # Can we now go to the page and empty the settings again?
        self.open_page("http://%s:%s/config/general" % (SAB_HOST, SAB_PORT))
        assert "/login" not in self.driver.current_url

        # Set the username and password
        username_imp = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[data-hide='username']")
        username_imp.clear()
        pass_inp = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "input[data-hide='password']")
        pass_inp.clear()

        # Submit and decline the restart-request (so no restart happens)
        self.answer_confirm(accept=False)
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.CLASS_NAME, "saveButton"))
        self.dismiss_restart_prompt()

        # Open any page and check we are NOT redirected to login (no credentials set)
        self.open_page("http://%s:%s/config/general" % (SAB_HOST, SAB_PORT))
        assert "/login" not in self.driver.current_url


class TestConfigCategories(SABnzbdBaseTest):
    category_name = "testCat"

    def test_page(self):
        # Test if base page works
        self.open_page("http://%s:%s/config/categories" % (SAB_HOST, SAB_PORT))

        # Add new category
        self.driver.find_elements(By.NAME, "newname")[1].send_keys("testCat")
        self.click_element(
            self.selenium_wrapper(
                self.driver.find_element, By.XPATH, "//button/text()[normalize-space(.)='Add']/parent::*"
            )
        )
        self.no_page_crash()
        assert self.category_name not in self.driver.page_source


class TestConfigRSS(SABnzbdBaseTest):
    rss_name = "_SeleniumFeed"

    def test_rss_basic_flow(self, httpserver: HTTPServer):
        # Setup the response for the NZB
        nzb_fp = create_and_read_nzb_fp("basic_rar5")
        httpserver.expect_request("/test_nzb.nzb").respond_with_data(nzb_fp.read())
        nzb_url = httpserver.url_for("/test_nzb.nzb")

        # Set the response for the RSS-feed, replacing the URL to the NZB
        with open(os.path.join(SAB_DATA_DIR, "rss_feed_test.xml")) as rss_file:
            rss_data = rss_file.read()
        rss_data = rss_data.replace("NZB_URL", nzb_url)
        httpserver.expect_request("/rss_feed.xml").respond_with_data(rss_data)
        rss_url = httpserver.url_for("/rss_feed.xml")

        # Test if base page works
        self.open_page("http://%s:%s/config/rss" % (SAB_HOST, SAB_PORT))

        # Uncheck enabled-checkbox for new feeds
        self.click_element(
            self.selenium_wrapper(
                self.driver.find_element, By.XPATH, '//form[@data-form="add-rss-feed"]//input[@name="enable"]'
            )
        )
        input_name = self.selenium_wrapper(
            self.driver.find_element, By.XPATH, '//form[@data-form="add-rss-feed"]//input[@name="feed"]'
        )
        input_name.clear()
        input_name.send_keys(self.rss_name)
        self.selenium_wrapper(
            self.driver.find_element, By.XPATH, '//form[@data-form="add-rss-feed"]//input[@name="uri"]'
        ).send_keys(rss_url)
        self.click_and_wait_for_page(
            self.selenium_wrapper(self.driver.find_element, By.XPATH, '//form[@data-form="add-rss-feed"]//button')
        )

        # Check if we have results
        tab_results = int(
            self.selenium_wrapper(self.driver.find_element, By.XPATH, '//a[@href="#rss-tab-matched"]/span').text
        )
        assert tab_results > 0

        # Check if it matches the number of rows
        tab_table_results = len(self.driver.find_elements(By.XPATH, '//div[@id="rss-tab-matched"]/table/tbody/tr'))
        assert tab_table_results == tab_results

        # Pause the queue do we don't download stuff
        assert get_api_result("pause") == {"status": True}

        # Download something
        download_btn = self.selenium_wrapper(
            self.driver.find_element, By.XPATH, '//div[@id="rss-tab-matched"]/table/tbody//button'
        )
        self.click_element(download_btn)

        # Does the page think it's a success?
        wait_for(
            lambda: "Added NZB" in download_btn.text,
            timeout=5,
            err_msg="Added NZB is not visible",
        )

        # Check if the fetch-request was added to the queue
        wait_for(
            lambda: len(get_api_result("queue")["queue"]["slots"]) > 0,
            timeout=10,
            err_msg="Did not find the RSS job in the queue",
        )

        # Let's remove this thing
        get_api_result("queue", extra_arguments={"name": "delete", "value": "all"})
        assert len(get_api_result("queue")["queue"]["slots"]) == 0

        # Unpause
        assert get_api_result("resume") == {"status": True}


class TestConfigServers(SABnzbdBaseTest):
    server_name = "_SeleniumServer"

    def open_config_servers(self):
        # Test if base page works
        self.open_page("http://%s:%s/config/server" % (SAB_HOST, SAB_PORT))
        self.scroll_to_top()

        # Show advanced options
        advanced_btn = self.selenium_wrapper(self.driver.find_element, By.NAME, "advanced-settings-button")
        if not advanced_btn.get_attribute("checked"):
            self.click_element(advanced_btn)

    def add_test_server(self):
        # Add server
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.ID, "addServerButton"))

        # The panel slides open, so its inputs only become interactable once it settles
        host_inp = WebDriverWait(self.driver, 15).until(EC.element_to_be_clickable((By.NAME, "host")))
        host_inp.clear()
        host_inp.send_keys(SAB_NEWSSERVER_HOST)

        # Change port
        port_inp = self.selenium_wrapper(self.driver.find_element, By.NAME, "port")
        port_inp.clear()
        port_inp.send_keys(SAB_NEWSSERVER_PORT)

        # Disable SSL for testing
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.NAME, "ssl"))

        # Test server-check
        result_box = self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "#addServerContent .result-box")
        self.click_element(
            self.selenium_wrapper(self.driver.find_element, By.CSS_SELECTOR, "#addServerContent .testServer")
        )
        wait_for(
            lambda: "Connection Successful" in result_box.text,
            timeout=5,
            err_msg="The connection test was not successful",
        )

        # Set test-servername
        self.selenium_wrapper(self.driver.find_element, By.ID, "displayname").send_keys(self.server_name)

        # Add and show details
        port_inp.send_keys(Keys.RETURN)
        wait_for(
            lambda: not self.selenium_wrapper(self.driver.find_element, By.ID, "host0").is_displayed(),
            timeout=2,
            err_msg="The Add Server interface did not close",
        )
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.CLASS_NAME, "showserver"))

    def remove_server(self):
        # Remove the first server, accepting the confirmation the click handler raises
        self.answer_confirm(accept=True)
        self.click_element(self.selenium_wrapper(self.driver.find_element, By.CLASS_NAME, "delServer"))
        self.wait_for_confirm()

        # Check that it's gone
        wait_for(
            lambda: self.server_name not in self.driver.page_source,
            timeout=2,
            err_msg=f"Page still contains '{self.server_name}'",
        )

    def test_add_and_remove_server(self):
        self.open_config_servers()
        self.add_test_server()
        self.remove_server()
