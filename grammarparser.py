# This python script privides a new format in which information can be analysed.
# This python script is dependent on lex and yacc.
# You have to install python module ply, which is an implementation of lex and yacc parsing tools.
# Install command for mac: pip install ply
#
# The grammar like this:
# Grammar:
#
# Rule 0     S' -> grammar
# Rule 1     grammar -> keyexpression_list
# Rule 2     grammar -> comments
# Rule 3     keyexpression_list -> keyexpression_list keyexpression_list
# Rule 4     keyexpression_list -> keyexpression
# Rule 5     keyexpression_list -> compound_keyexpression
# Rule 6     compound_keyexpression -> KEY_COMPOUND_START keyexpression_list KEY_COMPOUND_END
# Rule 7     keyexpression -> KEY_OR_PROPERTY_TOKEN KEY_SEPARATE property_expression_list KEY_END
# Rule 8     property_expression_list -> property_expression_list property_expression
# Rule 9     property_expression_list -> property_expression
# Rule 10    property_expression -> KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_NUMBER
# Rule 11    property_expression -> KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL KEY_OR_PROPERTY_TOKEN
# Rule 12    property_expression -> KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_STRING
# Rule 13    property_expression -> KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_LIST_BEGIN property_val_list PROPERTY_LIST_END
# Rule 14    property_expression -> empty
# Rule 15    property_val_list -> property_val_list PROPERTY_NUMBER
# Rule 16    property_val_list -> property_val_list KEY_OR_PROPERTY_TOKEN
# Rule 17    property_val_list -> PROPERTY_NUMBER
# Rule 18    property_val_list -> KEY_OR_PROPERTY_TOKEN
# Rule 19    property_val_list -> PROPERTY_STRING
# Rule 20    property_val_list -> empty
# Rule 21    comments -> COMMENT
# Rule 22    empty -> <empty>
#
# In the grammar something like KEY_** is defined below:

# KEY_OR_PROPERTY_TOKEN = '[a-zA-Z_][a-zA-Z_0-9]*'
# KEY_SEPARATE = '-->'
# KEY_END = ';'
# PROPERTY_EQUAL = '='
# KEY_COMPOUND_START = '{'
# KEY_COMPOUND_END = '}'
# PROPERTY_LIST_BEGIN = '\['
# PROPERTY_NUMBER = '[-+]{0,1}[0-9]+'    
# PROPERTY_STRING = '\"[^\"]*\"'
#
# We should know this:
# In the text, when the grammar meet #, the rest of this line will be considered as a comment which will be ignored by the grammar parser.
# In the text, you can only use these characters including a-zA-Z_0-9[]{}->;
# And you must know that --> is considered as a whole string, that is to say, you can't write a token or other string which contain - or >.
#
# So far, the grammar parser can parse the string which must accord with the grammar which is described above.
# If we need the grammar parser support to analyse the incomplete string whose first part accord with the grammar,
# we can update this script.
#

#

import ply.lex as lex  # Build the lexer
import ply.yacc as yacc  # Grammar analyse using yacc.

tokens = (
    'KEY_OR_PROPERTY_TOKEN',
    'KEY_SEPARATE',
    'PROPERTY_EQUAL',
    'PROPERTY_NUMBER',
    'PROPERTY_LIST_BEGIN',
    'PROPERTY_LIST_END',
    'PROPERTY_STRING',
    'KEY_END',
    'COMMENT',
    'KEY_COMPOUND_START',
    'KEY_COMPOUND_END',
)

states = (('singlecomment','inclusive'),)

# Tokens
t_KEY_OR_PROPERTY_TOKEN = r'[a-zA-Z_][a-zA-Z_0-9]*'
t_KEY_SEPARATE = r'-->'
t_KEY_END = r';'
t_PROPERTY_EQUAL = r'='
t_KEY_COMPOUND_START = r'{'
t_KEY_COMPOUND_END = r'}'
t_PROPERTY_LIST_BEGIN = r'\['
PROPERTY_LIST_BEGIN=r'['   # Notice that this variable don't contain escape character \.
t_PROPERTY_LIST_END = r']'
t_ignore = " \t"  # Ignored characters

def t_PROPERTY_NUMBER(t):
    r'[-+]{0,1}[0-9]+'
    t.value = int(t.value)
    return t

def t_PROPERTY_STRING(t):
    r'\"[^\"]*\"'
    t.value = t.value[1:len(t.value)-1]
    return t

def t_singlecomment(t):
    r'\#'
    #t.lexer.comment_start = t.lexer.lexpos - 1        # Record the starting position
    t.lexer.begin('singlecomment')                     # Enter 'singlecomment' state

def t_singlecomment_endcomment(t):
    r'\n'
    #t.value = t.lexer.lexdata[t.lexer.comment_start:t.lexer.lexpos+1]
    #t.type = "COMMENT"
    t.lexer.begin('INITIAL')
    pass

def t_singlecomment_COMMENT(t):
    r'.'
    pass

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")
    
def t_error(t):
    #print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)


# Below this line, we defined a new grammar format which is specified at the top of this python script.
# Get the token map from the lexer.  This is required.
def p_expression_grammar(p):
    '''grammar : keyexpression_list
               | comments'''
    p[0] = p[1]
    return p[0]

def p_expression_keyexpression_list(p):
    '''keyexpression_list : keyexpression_list keyexpression_list
                          | keyexpression
                          | compound_keyexpression
    '''
    # Keyexpression_list is a list whose element is keyexpression or compound_keyexpression.
    # Keyexpression is a tuple ,whose fist element is a KEY_OR_PROPERTY_TOKEN, whose second element is a property_expression_list.
    # compound_keyexpression is a list, whose every element is keyexpression or compound_keyexpression.
    # So if we want to recognize compound_keyexpression and keyexpression, you just judge its type.
    #
    # Actually a compound_keyexpression is keyexpression_list, which can contain keyexpression or compound_keyexpression.
    #
    if len(p) == 2:
        p[0] = [p[1]]   
    elif len(p) == 3:
        p[0] = []
        for x in p[1]:
            p[0].append(x)
        for x in p[2]:
            p[0].append(x)

def p_expression_compound_keyexpression(p):
    '''compound_keyexpression : KEY_COMPOUND_START keyexpression_list KEY_COMPOUND_END
    '''
    p[0] = p[2]
    pass

def p_expression_keyexpression(p):
    '''keyexpression : KEY_OR_PROPERTY_TOKEN KEY_SEPARATE property_expression_list KEY_END
    '''
    # keyexpression is a tuple.
    # The first element is KEY_OR_PROPERTY_TOKEN whose type is string.
    # The second element is property_expression_list which is a list of property_expression list.
    if len(p[3][0]) == 0:
        p[0] = (p[1], [])
    else:
        p[0] = (p[1], p[3])

# value_expressions is consisted of several value_expression
def p_expression_property_expression_list(p):
    '''property_expression_list : property_expression_list property_expression
                                | property_expression
    '''
    # property_expression_list is a list of property_expression.
    if len(p) == 2:
        p[0] = [p[1]]
    elif len(p) == 3:
        p[0] = []
        for x in p[1]:
            p[0].append(x)
        p[0].append(p[2])
        pass
    pass

def p_expression_property_expression(p):
    '''property_expression : KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_NUMBER
                           | KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL KEY_OR_PROPERTY_TOKEN
                           | KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_STRING
                           | KEY_OR_PROPERTY_TOKEN PROPERTY_EQUAL PROPERTY_LIST_BEGIN property_val_list PROPERTY_LIST_END
                           | empty
    '''
    # property_expression is a list,
    # whose first element is KEY_OF_VALUE_TOKEN,
    # whose second element is PROPERTY_EQUAL,
    # whose third element maybe is one of these type PROPERTY_NUMBER, KEY_OR_PROPERTY_TOKEN, PROPERTY_STRING or a property_val_list
    #
    # Of course property_expression maybe is an empty list.
    if len(p) == 4:
        p[0]  = [p[1], p[2], p[3]]
    elif len(p) == 6:
        p[0]  = [p[1], p[2], p[4]]
    else:
        p[0] = []
    pass

def p_expression_property_val_list(p):
    '''property_val_list : property_val_list PROPERTY_NUMBER
                         | property_val_list KEY_OR_PROPERTY_TOKEN
                         | property_val_list PROPERTY_STRING
                         | PROPERTY_NUMBER
                         | KEY_OR_PROPERTY_TOKEN
                         | PROPERTY_STRING
                         | empty
    '''
    # property_val_list is a list whose element will be one of these types,
    # PROPERTY_NUMBER,KEY_OR_PROPERTY_TOKEN, PROPERTY_STRING.    
    if len(p) == 3:
        p[0] = []
        for x in p[1]:
            p[0].append(x)
        p[0].append(p[2])
    else:
        if p[1] == None:
            p[0] = []
        else:
            p[0] = [p[1]]    
    pass

def p_expression_comment(p):
    'comments : COMMENT'
    # Although the COMMENT will be output by lexer, it will be ignored by yacc parser.
    pass

def p_empty(p):
    'empty :'
    pass

# Error rule for syntax errors
def p_error(p):
    print p
    print "Syntax error in input!"


# Below this line, we defined some user-friendly interface.
#
def grammar_parse(whole_string, debug_flag=0):
    '''
    This function will create a parser and parse the whole string.
    usage: list_output = grammar_parse(whole_string)
    '''
    lexer = lex.lex(debug=debug_flag)
    # Debug the lexer
    if debug_flag:
        lexer.input(whole_string)
        while True:
            tok = lexer.token()
            if not tok: break      # No more input
            print tok

    parser = yacc.yacc()
    result = parser.parse(whole_string,lexer)
    return result


def grammar_parse_keyexpression_get_name(tuple_in):
    '''
    This function can get the name of keyexpression.
    keyexpression is a tuple.
    Usage: str_name = grammar_parse_keyexpression_get_name(tuple_in)
    '''
    if type(tuple_in) == tuple:
        return tuple_in[0]
    else:
        return 

# Parse a tuple 
def grammar_parse_keyexpression(tuple_in, tuple_name, property_name):
    '''
    This function can get the property value of keyexpression.
    Usage: pro_val = grammar_parse_keyexpression(tuple_in, tuple_name, property_name)
    '''    
    if type(tuple_in) == tuple:
        if tuple_in[0] == tuple_name:
            for val_list in tuple_in[1]:
                if len(val_list) == 3:
                    if val_list[0] == property_name:
                        return (True,val_list[2])
    return (False, None)
    
def grammar_parse_keyexpression_generate(tuple_name):
    '''
    Generate a tuple which don't have any property.
    You can add some properties in it later.
    Usage: tuple_out = grammar_parse_keyexpression_generate(tuple_name)
    '''
    return (tuple_name, [])

def grammar_parse_keyexpression_del_property(tuple_in, tuple_name, property_name):
    '''
    Del a property of a tuple.
    Usage: grammar_parse_keyexpression_del_property(tuple_in, tuple_name, property_name)
    '''
    if type(tuple_in) == tuple:
        if tuple_in[0] == tuple_name:
            # Traverse property list
            # If we find a property whose name is property_name,
            # we delete this property.
            for idx in range(len(tuple_in[1])):
                if len(tuple_in[1][idx]) == 3:
                    if tuple_in[1][idx][0] == property_name:
                        del tuple_in[1][idx]
                        return            
    else:
        return

def grammar_parse_keyexpression_modify_property(tuple_in, tuple_name, property_name, property_val):
    '''
    Modify a property of a tuple.
    Usage: grammar_parse_keyexpression_modify_property(tuple_in, tuple_name, property_name, property_val):
    '''
    if type(tuple_in) == tuple:
        if tuple_in[0] == tuple_name:
            # Traverse property list
            # If we find a property whose name is property_name,
            # we modify its value then we return.
            # If we don't find a property whose name is property_name, 
            # we add a new property whose name and value is proprety_name and property_val respectively.            
            for idx in range(len(tuple_in[1])):
                if len(tuple_in[1][idx]) == 3:
                    if tuple_in[1][idx][0] == property_name:
                        tuple_in[1][idx][2] = property_val
                        return
            tuple_in[1].append([property_name, "=", property_val])
            return
    else:
        return

#
# List may contain list and tuple.
# Tuple may contain a token and a list which contain some property.
# 
# Parase a list which maybe contains a tuple or a list which maybe contains a tuple or a list ....
# return a list of tuple whose first element is token_name
#
def grammar_parse_keyexpression_list(list_in, token_name):
    '''
    Parase a list which maybe contains a tuple or a list which maybe contains a tuple or a list ....
    Return a list of tuple whose first element is token_name.
    Usage: list_out = grammar_parse_keyexpression_list(list_in, token_name)
    '''
    res_list = []
    def parse_list_inner(list_in, token_name):
        for iter in list_in:
            if type(iter) == tuple:
                if iter[0] == token_name:
                    res_list.append(iter)
            elif type(iter) == list:
                parse_list_inner(iter, token_name)
    parse_list_inner(list_in, token_name)
    return res_list

def grammar_parse_insert_keyexpression(list_in, tuple_in):
    if tuple_in:
        list_in.append(tuple_in)
    
# Generate a string of a list.
# You can store this string in a file or do something else.
def grammar_parse_generate_string(list_in):
    '''
    Generate a string of a list.
    Usage: str_out = grammar_parse_generate_string(list_in)
    '''
    def generate_string_for_tuple(tuple_in):
        def generate_string_for_property_val(val_in):
            val_string=""
            if type(val_in) == str:
                val_string = "\"" + val_in + "\""
            elif type(val_in) == int:
                val_string = str(val_in)
            elif type(val_in) == list:
                val_string = PROPERTY_LIST_BEGIN
                for iter in val_in:
                    val_string += generate_string_for_property_val(iter) + " "                    
                val_string += t_PROPERTY_LIST_END
            return val_string
            
        if type(tuple_in) == tuple:
            # Generate a string which stand for tuple.
            # Generate a string which stand for its all property.
            # Append this sting to whole_string.
            tuple_string = tuple_in[0] + "   " + t_KEY_SEPARATE + "   "
            for property_iter in tuple_in[1]:
                if len(property_iter) == 3:
                    property_string = property_iter[0] + property_iter[1] + generate_string_for_property_val(property_iter[2]) + " "
                    tuple_string += property_string
            tuple_string += t_KEY_END + "\n"
            return tuple_string
        elif type(tuple_in) == list:
            return ""

    def generate_string_inner(list_in, indent_level):
        indent_string = ""
        indent_tab = "    "
        for i in range(indent_level):
            indent_string += indent_tab

        whole_string = ""
        #print indent_string + t_KEY_COMPOUND_START
        whole_string += indent_string + t_KEY_COMPOUND_START + "\n"
        for element in list_in:
            if type(element) == tuple:                
                whole_string += indent_string + indent_tab + generate_string_for_tuple(element)
            elif type(element) == list:
                #indent_level += 1
                whole_string += generate_string_inner(element, indent_level + 1)
        #print indent_string + t_KEY_COMPOUND_END
        whole_string += indent_string + t_KEY_COMPOUND_END + "\n"
        return whole_string

    #This string will be returned at the end of function.
    whole_string = ""
    for element in list_in:
        #print x
        if type(element) == tuple:
            whole_string += generate_string_for_tuple(element)
        elif type(element) == list:
            whole_string += generate_string_inner(element, 0)
    return whole_string

if __name__ == "__main__":
    # execute only if run as a script
    import sys
    filename = sys.argv[1]
    f = open(filename,"r")
    whole_line = f.read()
    f.close()
    grammar_list = grammar_parse(whole_line, debug_flag=1)
    print grammar_list

