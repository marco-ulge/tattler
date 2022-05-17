from mongoengine import StringField, IntField, FloatField, BooleanField, \
    SortedListField, Document, EmbeddedDocument, EmbeddedDocumentField


class RegexMatch(EmbeddedDocument):
    occurrence_type = StringField(
        choices=('Whitelist', 'Blacklist', 'Single string'),
        required=True
        )
    filename = StringField(required=True, max_length=100)
    line_number = IntField(required=True)
    occurrence = StringField(required=True, max_length=2000)
    rule = StringField(required=True)
    meta = {'allow_inheritance': True}


class PropertiesFileMatch(RegexMatch):
    specific_string_occurrence = StringField(required=True)


class SingleStringMatch(RegexMatch):
    shannon_entropy = FloatField(required=True)
    specific_string_occurrence = StringField(
        choices=('password/secret', 'hardcoded_hash')
        )
    blacklist_match = BooleanField(required=True)


def store_regex_results(occurrence_type, filename,
                              line_number, single_result, rule):
    current_result = RegexMatch(
        occurrence_type=occurrence_type,
        filename=filename,
        line_number=line_number,
        occurrence=single_result,
        rule=rule
    )
    return current_result


def store_properties_file_results(occurrence_type, filename, line_number,
                                  single_results, specific_string_occurrence):
    current_result = PropertiesFileMatch(
        occurrence_type=occurrence_type,
        filename=filename,
        line_number=line_number,
        occurrence=single_results,
        specific_string_occurrence=specific_string_occurrence
    )
    return current_result


def store_single_string_results(occurrence_type, filename, line_number,
                                single_results, shannon_entropy,
                                specific_string_occurrence, blacklist_match):
    current_result = SingleStringMatch(
        occurrence_type=occurrence_type,
        filename=filename,
        line_number=line_number,
        occurrence=single_results,
        shannon_entropy=shannon_entropy,
        specific_string_occurrence=specific_string_occurrence,
        blacklist_match=blacklist_match
    )
    return current_result
