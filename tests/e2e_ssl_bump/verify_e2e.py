import asyncio
import logging

import httpx
import redis.asyncio as redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def verify_e2e():
    logger.info("--- Starting Enhanced E2E Integrated Test ---")

    # 0. Connect to Redis to monitor state
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)

    async def get_redis_info():
        try:
            keys = await r.keys("*")
            logger.info(f"Current Redis Keys: {keys}")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")

    await get_redis_info()

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        # [Test 1] Sending Clean File
        logger.info("[Test 1] Sending Clean File...")
        try:
            resp = await client.get(
                "https://localhost:8443/clean.txt", headers={"Host": "test.example.com"}
            )
            logger.info(f"Response Status: {resp.status_code}")
            if resp.status_code == 200:
                logger.info("SUCCESS: Clean file reached destination.")
            else:
                logger.error(
                    f"FAILED: Clean file returned {resp.status_code}. Text: {resp.text[:100]}"
                )
        except Exception as e:
            logger.error(f"Test 1 Error: {e}")

        await get_redis_info()

        # [Test 2] Sending Infected File
        logger.info("[Test 2] Sending Infected File (EICAR)...")
        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        try:
            resp = await client.post(
                "https://localhost:8443/upload",
                headers={"Host": "test.example.com"},
                content=eicar,
            )
            logger.info(f"Response Status: {resp.status_code}")
            if resp.status_code == 403:
                logger.info("SUCCESS: Infected file was blocked (403).")
            else:
                logger.error(
                    f"FAILED: Infected file returned {resp.status_code}. Expected 403."
                )
        except Exception as e:
            logger.error(f"Test 2 Error: {e}")

        await get_redis_info()

        # [Test 3] Webhook Verification
        logger.info("[Test 3] Verifying Webhook Notification...")
        await asyncio.sleep(5)  # Wait for processing
        try:
            resp = await client.get("http://localhost:3001/logs")
            logger.info(f"Mock Console logs length: {len(resp.text)}")
            if "e2e-test-tenant" in resp.text:
                logger.info("SUCCESS: Webhook notification verified.")
            else:
                logger.error("FAILED: Webhook for tenant 'e2e-test-tenant' not found.")
        except Exception as e:
            logger.error(f"Test 3 Error: {e}")

    logger.info("--- Enhanced E2E Integrated Test Completed ---")


if __name__ == "__main__":
    asyncio.run(verify_e2e())
