from typing import Dict, Any

from .models import BotSubmission, XSSAttack
from . import utils
from django.db import transaction


@transaction.atomic
def create_bot_record(
    cleaned_data: Dict[str, Any], meta_data: Dict[str, Any]
) -> BotSubmission:
    email = utils.get_email(cleaned_data)

    # analytics
    ip_address, full_ip_address = utils.get_client_ip(meta_data)
    agent = utils.get_bot_agent(meta_data)
    language = utils.get_bot_language(meta_data)
    referer = utils.get_bot_referer(meta_data)

    bot_submission = BotSubmission.objects.create(
        name=cleaned_data.get("name"),
        email=email,
        message=cleaned_data.get("message"),
        # analytics data
        ip_address=ip_address,
        full_ip_address=full_ip_address,
        agent=agent,
        language=language,
        referer=referer,
    )

    xss_attacks = utils.scan_xss(cleaned_data)
    if xss_attacks:
        objects_to_create = [
            XSSAttack(
                submission=bot_submission,
                field=attack["field"],
                pattern=attack["pattern"],
                snippet=attack["snippet"],
            )
            for attack in xss_attacks
        ]
        XSSAttack.objects.bulk_create(objects_to_create)

    return bot_submission
