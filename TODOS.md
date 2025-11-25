# Test the bot submission API

Problems I'm learning

PROBLEM #1 -
Add existing attack categories to each BotEvent

EachBotEvent has a Many to One relagtionship with Attacks
Each Attack has it's own category
How can I display all available categories for each Event
annotate a new field in the query set and use ArrayAgg and distinct=True to group and sort list values.

Want to filter by many cats
Create a filterset for this field. Should accept multiple attack cats
To accept multiple use MultipleChoiceFilter -->
iterate through each category in the multi choice and apply each as a filter param with Q()

PROBLEM #2 -
How can I group by attack cattegory, rank by higehst number of attacks, and list the three most common paths used.

Gorup by attack category order desc
for each category filter the queryset group by path and order desc grab top 3
