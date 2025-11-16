#include "../include/domain/param/IOPairParam.h"

IOParam IOPairParam::get_input()
{
    return *(this->input.get());
}

IOParam IOPairParam::get_output()
{
    return *(this->output.get());
}
